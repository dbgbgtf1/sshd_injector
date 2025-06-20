# sshd_injector
A stupid and undone tools to inject some system proc

## idea

1. 拉取目标系统的sshd binary
2. 使用Python解析`open`的got表偏移以及`rx`段剩余可用起始位置
3. 将payload填充到C模板中并编译
4. injector进程读取`/proc/$(pgrep sshd-session)/maps`，找到PIE，并确定要往哪个地址注入
5. ptrace注入got表，劫持`open`到shellcode，如果是`/root/.ssh/authorized_keys`，
    那么`open(FILE), memfd_create(), sendfile(fd, memfd), close(fd), return memfd`

`b'/root/.ssh/authorized_keys'`
```x86asm
// cmp rsi, FILE_PATH
mov rax, ORIGINAL_OPEN_ADDR
jne original
call rax

original:
jmp rax
```
