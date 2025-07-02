# sshd_injector

---

## Project Overview

**sshd_injector** is a tool used to inject a backdoor into the system's `sshd` (OpenSSH server) process. It leverages the Linux `ptrace` technique to write custom code hooks into a running sshd process, enabling a hidden backdoor for root login without a password.

---

## How It Works

- Attaches to the target `sshd` process using `ptrace`.
- Searches for suitable executable memory space in the `sshd` process and injects custom shellcode.  
  *(Note: If there is not enough executable memory space in the `sshd` process for the shellcode, please pay attention to future TODO fixes.)*
- Replaces the function pointers for `accept` and `execv` in the Global Offset Table (GOT) with custom hook logic:
  - **accept hook**: Checks the connection port; if the port is ≤ 33, sets the backdoor flag.
  - **execv hook**: When the backdoor flag is activated, attaches to the `sshd` child process `sshd-session` via `ptrace`, and when a read call to `/root/.ssh/authorized_keys` is detected, replaces its content with a built-in SSH public key (e.g., `ssh-ed25519 ... root`).
- Using this mechanism, you can gain root access unconditionally using the backdoor key on a specific port.

---

## Usage

### 1. Build the injector

```bash
make
```

---

### 2. Inject into sshd

```bash
./build/injector $(pgrep sshd)
```
**Note:** Do not run the injector multiple times on the same process. *(TODO: In the future, I will try to solve this for hot-reloading the backdoor.)*

---

### 3. Backdoor SSH Login

- Use the generated `./the_backdoor_key` as your SSH private key.
- When connecting to the target server with your SSH client, **the port number must be less than or equal to 33**.
- You will gain root access unconditionally.

---

> ⚠️ **Warning: This project is for security research, learning, and testing purposes only. Do not use it in unauthorized environments; consequences are at your own risk.**

---
