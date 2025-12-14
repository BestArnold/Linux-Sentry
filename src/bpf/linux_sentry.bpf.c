// src/bpf/linux_sentry.bpf.c
// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Sentry - eBPF内核监控程序
 * 监控系统的文件访问和程序执行，根据文件路径和访问模式评估风险
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16   /* 进程名最大长度 */
#define FILENAME_LEN  128  /* 文件路径最大长度 */

/* 文件打开标志宏定义 */
#ifndef O_RDONLY
#define O_RDONLY 00        /* 只读打开 */
#define O_WRONLY 01        /* 只写打开 */
#define O_RDWR   02        /* 读写打开 */
#endif

#ifndef O_CREAT
#define O_CREAT 0100       /* 创建文件 */
#endif

#ifndef O_TRUNC
#define O_TRUNC 01000      /* 截断文件 */
#endif

/* 风险等级枚举 */
enum risk_level {
    RISK_IGNORE = 0,  /* 忽略：低风险，不通知用户 */
    RISK_INFO   = 1,  /* 信息：中等风险，记录但不需确认 */
    RISK_ALERT  = 2,  /* 警告：高风险，需要用户确认 */
};

/* 进程信息结构体 */
struct proc_info {
    __u32 pid;                /* 进程ID */
    __u32 ppid;               /* 父进程ID */
    char  comm[TASK_COMM_LEN];/* 进程名称 */
};

/* 文件事件结构体，发送到用户空间 */
struct file_event {
    __u32 pid;                /* 进程ID */
    __u32 ppid;               /* 父进程ID */
    __u32 flags;              /* 文件打开标志 */
    __u8  risk_level;         /* 风险等级 */
    __u8  pad[3];             /* 填充字节，对齐用 */
    char  comm[TASK_COMM_LEN];/* 进程名称 */
    char  filename[FILENAME_LEN]; /* 文件路径 */
};

/* BPF映射定义 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct proc_info);
    __uint(max_entries, 10240);
} proc_map SEC(".maps");

/* 环形缓冲区映射，用于向用户空间发送事件 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/*
 * 监控的关键系统文件路径
 * 注意：必须使用数组 [] 而不是指针 *，以便 sizeof() 工作正常
 */
const char etc_prefix[]     = "/etc/";                /* /etc目录前缀 */
const char shadow_path[]    = "/etc/shadow";          /* 密码文件 */
const char sudoers_path[]   = "/etc/sudoers";         /* sudo配置文件 */
const char sshd_path[]      = "/etc/ssh/sshd_config"; /* SSH服务配置 */
const char cron_allow[]     = "/etc/cron.allow";      /* cron允许列表 */
const char cron_deny[]      = "/etc/cron.deny";       /* cron拒绝列表 */
const char passwd_path[]    = "/etc/passwd";          /* 用户账户文件 */
const char ldso_cache[]     = "/etc/ld.so.cache";     /* 动态链接器缓存 */
const char localtime_path[] = "/etc/localtime";       /* 本地时区文件 */

/*
 * 字符串比较辅助函数
 * 比较两个字符串是否完全相等
 */
static __always_inline bool str_equal(const char *a, const char *b, int max_len)
{
    int i;
    for (i = 0; i < 64; i++) {
        char ca, cb;
        if (i >= max_len) break;
        ca = a[i];
        cb = b[i];
        if (ca != cb) return false;
        if (ca == '\0') break;
    }
    return true;
}

/*
 * 字符串前缀匹配辅助函数
 * 检查字符串s是否以prefix开头
 */
static __always_inline bool has_prefix(const char *s, const char *prefix, int max_len)
{
    int i;
    for (i = 0; i < 16; i++) {
        char c;
        if (i >= max_len) break;
        c = prefix[i];
        if (c == '\0') break;
        if (s[i] != c) return false;
    }
    return true;
}

/*
 * 基础风险评估：根据文件路径判断风险等级
 * 高风险文件：shadow, sudoers, sshd_config, cron.allow/deny
 * 中等风险文件：passwd, /etc目录下的其他文件
 * 低风险文件：ld.so.cache, localtime等
 */
static __always_inline enum risk_level base_risk_from_path(const char *fn)
{
    /* 高风险系统文件 - 直接影响系统安全 */
    if (str_equal(fn, shadow_path, sizeof(shadow_path))) return RISK_ALERT;
    if (str_equal(fn, sudoers_path, sizeof(sudoers_path))) return RISK_ALERT;
    if (str_equal(fn, sshd_path, sizeof(sshd_path))) return RISK_ALERT;
    if (str_equal(fn, cron_allow, sizeof(cron_allow))) return RISK_ALERT;
    if (str_equal(fn, cron_deny, sizeof(cron_deny))) return RISK_ALERT;

    /* 中等风险文件 - 包含重要系统信息 */
    if (str_equal(fn, passwd_path, sizeof(passwd_path))) return RISK_INFO;

    /* 低风险文件 - 频繁访问的系统文件 */
    if (str_equal(fn, ldso_cache, sizeof(ldso_cache))) return RISK_IGNORE;
    if (str_equal(fn, localtime_path, sizeof(localtime_path))) return RISK_IGNORE;

    /* /etc目录下的其他文件为中等风险 */
    if (has_prefix(fn, etc_prefix, sizeof(etc_prefix))) return RISK_INFO;

    return RISK_IGNORE;
}

/*
 * 综合风险评估：结合文件路径和访问模式
 * 写、创建、截断操作会将风险升级为ALERT
 */
static __always_inline enum risk_level risk_from_path_and_flags(const char *fn, __u32 flags)
{
    enum risk_level r = base_risk_from_path(fn);
    if (r == RISK_IGNORE) return RISK_IGNORE;

    /* 如果包含写、创建或截断操作，升级为ALERT */
    if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))
        return RISK_ALERT;

    return r;
}

/*
 * execve系统调用跟踪点处理函数
 * 记录新进程的基本信息到proc_map
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    struct proc_info info = {};
    struct task_struct *task;
    __u32 ppid = 0;

    /* 获取进程ID和进程名 */
    info.pid = tgid;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    /* 获取父进程ID */
    task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        ppid = BPF_CORE_READ(task, real_parent, tgid);
    }
    info.ppid = ppid;

    /* 将进程信息存储到哈希映射中 */
    bpf_map_update_elem(&proc_map, &tgid, &info, BPF_ANY);
    return 0;
}

/*
 * openat系统调用跟踪点处理函数
 * 监控文件访问，评估风险并发送事件到用户空间
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename_ptr = (const char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];
    struct file_event *ev;
    struct proc_info *pinfo;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    char tmp[64];
    enum risk_level risk;

    /* 从用户空间读取文件名 */
    if (bpf_probe_read_user_str(tmp, sizeof(tmp), filename_ptr) < 0)
        return 0;

    /* 评估访问风险 */
    risk = risk_from_path_and_flags(tmp, flags);
    if (risk == RISK_IGNORE)
        return 0;

    /* 查找进程信息 */
    pinfo = bpf_map_lookup_elem(&proc_map, &tgid);
    if (!pinfo) return 0;

    /* 分配环形缓冲区空间 */
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    /* 填充事件数据 */
    ev->pid        = pinfo->pid;
    ev->ppid       = pinfo->ppid;
    ev->flags      = flags;
    ev->risk_level = (__u8)risk;
    __builtin_memcpy(ev->comm, pinfo->comm, TASK_COMM_LEN);

    /* 读取完整文件路径 */
    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), filename_ptr);

    /* 提交事件到用户空间 */
    bpf_ringbuf_submit(ev, 0);
    return 0;
}