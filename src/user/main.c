// src/user/main.c
// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Sentry - 用户空间监控程序
 * 负责接收BPF程序捕获的文件系统事件，并根据风险等级进行处理
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define FILENAME_LEN   128  /* 文件名最大长度 */
#define TASK_COMM_LEN  16   /* 进程名最大长度 */

/* 退出标志，用于信号处理 */
static volatile sig_atomic_t exiting = 0;

/*
 * libbpf日志打印回调函数
 */
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/*
 * 文件事件结构体，与BPF程序中的定义保持一致
 */
struct file_event {
    __u32 pid;                /* 进程ID */
    __u32 ppid;               /* 父进程ID */
    __u32 flags;              /* 文件打开标志 */
    __u8  risk_level;         /* 风险等级: 0-忽略, 1-信息, 2-警告 */
    __u8  pad[3];             /* 填充字节，对齐用 */
    char  comm[TASK_COMM_LEN];/* 进程名称 */
    char  filename[FILENAME_LEN]; /* 文件路径 */
};

#define MAX_ALLOWED_PIDS 1024  /* 允许的最大进程ID数量 */
static __u32 allowed_pids[MAX_ALLOWED_PIDS];  /* 允许的进程ID列表 */
static int allowed_pids_cnt = 0;              /* 当前允许的进程ID计数 */

/*
 * 检查进程ID是否在允许列表中
 */
static int is_pid_allowed(__u32 pid)
{
    for (int i = 0; i < allowed_pids_cnt; i++) {
        if (allowed_pids[i] == pid) return 1;
    }
    return 0;
}

/*
 * 将进程ID添加到允许列表中
 */
static void add_allowed_pid(__u32 pid)
{
    if (is_pid_allowed(pid)) return;
    if (allowed_pids_cnt >= MAX_ALLOWED_PIDS) return;
    allowed_pids[allowed_pids_cnt++] = pid;
}

/*
 * 将风险等级转换为字符串
 */
static const char *risk_to_str(__u8 r)
{
    switch (r) {
    case 2: return "ALERT";  /* 高风险 */
    case 1: return "INFO";   /* 信息级别 */
    default: return "IGNORE";/* 忽略 */
    }
}

/*
 * 将文件打开标志转换为可读字符串
 */
static const char *flags_to_str(__u32 flags, char *buf, size_t sz)
{
    int first = 1;
    buf[0] = '\0';
    if ((flags & 03) == 0) { snprintf(buf, sz, "RDONLY"); first = 0; }    /* 只读 */
    else if ((flags & 03) == 1) { snprintf(buf, sz, "WRONLY"); first = 0; }/* 只写 */
    else if ((flags & 03) == 2) { snprintf(buf, sz, "RDWR"); first = 0; }  /* 读写 */
    if (flags & 0100) { snprintf(buf + (first?0:strlen(buf)), sz-strlen(buf), "%sCREAT", first?"":"|"); first=0; } /* 创建 */
    if (flags & 01000) { snprintf(buf + (first?0:strlen(buf)), sz-strlen(buf), "%sTRUNC", first?"":"|"); first=0; } /* 截断 */
    if (first) snprintf(buf, sz, "0x%x", flags);
    return buf;
}

/*
 * 信号处理函数，用于优雅退出
 */
static void handle_signal(int sig) { exiting = 1; }

/*
 * 读取用户输入的y/n字符
 */
static char read_yes_no_char(void)
{
    char buf[64];
    for (;;) {
        if (!fgets(buf, sizeof(buf), stdin)) return 0;
        char *p = buf;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\n' || *p == '\0') {
            printf("No input detected, please enter 'y' or 'n'.\n");
            fflush(stdout);
            continue;
        }
        return *p;
    }
}

/*
 * 处理从BPF程序接收的事件
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct file_event *ev = data;
    const char *level = risk_to_str(ev->risk_level);
    char flags_buf[64];
    const char *flags_desc = flags_to_str(ev->flags, flags_buf, sizeof(flags_buf));

    printf("[%s] pid=%d ppid=%d comm=%s flags=%s path=%s\n",
           level, ev->pid, ev->ppid, ev->comm, flags_desc, ev->filename);
    fflush(stdout);

    /* 只有高风险事件需要用户确认 */
    if (ev->risk_level != 2) return 0;

    /* 检查进程是否已被允许 */
    if (is_pid_allowed(ev->pid)) {
        printf("Process %u (%s) is already allowed, skipping prompt.\n", ev->pid, ev->comm);
        fflush(stdout);
        return 0;
    }

    /* 暂停进程，等待用户决定 */
    if (kill((pid_t)ev->pid, SIGSTOP) != 0) {
        printf("Failed to pause process %u (errno=%d).\n", ev->pid, errno);
        return 0;
    }

    printf("Process %u (%s) paused. Allow? [y/N]: ", ev->pid, ev->comm);
    fflush(stdout);

    /* 读取用户输入并执行相应操作 */
    char c = read_yes_no_char();
    if (c == 'y' || c == 'Y') {
        add_allowed_pid(ev->pid);
        kill((pid_t)ev->pid, SIGCONT);
        printf("Process %u resumed.\n", ev->pid);
    } else {
        kill((pid_t)ev->pid, SIGKILL);
        printf("Process %u terminated.\n", ev->pid);
    }
    fflush(stdout);
    return 0;
}

/*
 * 主函数：初始化BPF程序并处理事件
 */
int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_map *map;
    struct ring_buffer *rb = NULL;
    int err;

    /* 设置libbpf的严格模式和打印回调 */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* 注册信号处理函数 */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* 加载BPF对象文件 */
    obj = bpf_object__open_file("build/linux_sentry.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file. (Are you running from project root?)\n");
        return 1;
    }

    /* 加载BPF程序到内核 */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    /* 附加到跟踪点 */
    struct bpf_program *prog_exec = bpf_object__find_program_by_name(obj, "handle_execve");
    if (!prog_exec) { fprintf(stderr, "Missing handle_execve\n"); goto cleanup; }
    bpf_program__attach(prog_exec);

    struct bpf_program *prog_open = bpf_object__find_program_by_name(obj, "handle_openat");
    if (!prog_open) { fprintf(stderr, "Missing handle_openat\n"); goto cleanup; }
    bpf_program__attach(prog_open);

    /* 查找事件映射 */
    map = bpf_object__find_map_by_name(obj, "events");
    if (!map) { fprintf(stderr, "Failed to find events map\n"); goto cleanup; }

    /* 创建环形缓冲区以接收事件 */
    rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "Failed to create ring buffer\n"); goto cleanup; }

    printf("Linux Sentry started. Press Ctrl+C to exit.\n");

    /* 主循环：轮询事件 */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
    }

    printf("Exiting...\n");
cleanup:
    /* 清理资源 */
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}