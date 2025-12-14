# Linux Sentry: eBPF-based File Access Monitor & Blocker

> 东南大学计软智学院Linux 内核技术课程小组实验

这是一个基于 eBPF (CO-RE) 的 Linux 文件访问监控与防御实验项目。
它运行在 Linux 6.8+ 内核上，能够实时拦截对敏感文件（如 `/etc/shadow`）的访问，并在用户态提供交互式的“允许/拒绝”控制。

## ✨ 功能特性

*   **内核态感知**：使用 `tracepoint` 挂载 `sys_enter_openat` 和 `sys_enter_execve`。
*   **实时拦截**：检测到高危文件访问（如写操作或访问 `/etc/shadow`）时，自动发送 `SIGSTOP` 暂停目标进程。
*   **用户交互**：管理员在终端收到告警，输入 `y/n` 决定放行或终止进程。
*   **CO-RE 架构**：一次编译，到处运行。
*   **静态链接 Libbpf**：自带最新版 `libbpf`，解决系统库版本过低导致的 BTF 兼容性问题。

## 🛠️ 环境要求

*   **OS**: Linux (推荐 Ubuntu 22.04/24.04)
*   **Kernel**: 5.10+ (已在 6.8.0-87-generic 验证)
*   **Tools**: clang, llvm, make, git, bpftool, libelf-dev


## 📂 目录结构

*   `src/bpf/`: eBPF 内核态代码 (`.bpf.c`) 和 `vmlinux.h`。
*   `src/user/`: 用户态加载器与交互逻辑代码。
*   `src/libbpf/`: 嵌入的 libbpf 源码（用于静态链接）。
*   `build/`: 编译产物。
```text
linux_sentry/
├── .gitignore               # (新增) Git 忽略文件
├── Makefile                 # (最终版) 包含 libbpf 静态编译逻辑
├── README.md                # (新增) 项目说明文档
└── src/
    ├── libbpf/              # (空文件夹，稍后作为 git submodule 或 clone 放入)
    ├── bpf/
    │   └── linux_sentry.bpf.c
    └── user/
        └── main.c
```


## 🚀 快速开始


### 1. 安装依赖

```bash
sudo apt update
sudo apt install clang llvm libelf-dev make git linux-tools-$(uname -r) linux-headers-$(uname -r)
```

### 2. 克隆项目与 Libbpf

本项目依赖最新版 `libbpf`，需要将其克隆到本地目录：

```bash
# 如果你是 clone 的这个仓库，请更新 submodule
# git submodule update --init --recursive

# 如果是手动搭建，请执行：
mkdir -p src/libbpf
git clone https://github.com/libbpf/libbpf.git src/libbpf
```

### 3. 生成 vmlinux.h

生成当前内核的头文件（CO-RE 核心依赖）：

```bash
make vmlinux
```

### 4. 编译

执行 `make` 将自动编译本地 libbpf 并构建项目：

```bash
make
```

编译成功后，将在 `build/` 目录下生成：
*   `linux_sentry` (用户态控制程序)
*   `linux_sentry.bpf.o` (内核态 BPF 字节码)

### 5. 运行

**注意**：加载 eBPF 程序需要 root 权限。

```bash
sudo ./build/linux_sentry
```

## 🧪 实验验证

保持 `linux_sentry` 运行，打开一个新的终端窗口进行测试。

**测试 1：普通访问（触发 INFO 日志）**
```bash
cat /etc/passwd
```
*结果*：Sentry 终端显示 `[INFO] ...`，操作正常放行。

**测试 2：高危访问（触发拦截）**
```bash
sudo cat /etc/shadow
```
*结果*：
1.  `cat` 命令卡住（进程被挂起）。
2.  Sentry 终端提示：`Allow process ...? [y/N]`。
3.  输入 `n` -> 进程被终止；输入 `y` -> 进程继续执行。

注：该文件由 `claude code` + `GLM-4.6` 生成