mov rax, 0x38
push rax
push rdi
push rsi
push rdx
push r10
push r8
push r9

/* open(file='/dev/pts/1', oflag=1, mode=0) */
push 0x1010101 ^ 0x312f
xor dword ptr [rsp], 0x1010101
mov rax, 0x7374702f7665642f
push rax
mov rdi, rsp
xor edx, edx /* 0 */
mov rsi, 0x1
/* call open() */
push SYS_open /* 2 */
pop rax
syscall

/* write(fd=/dev/pts/2, buf='this is from tracee', n=0x20) */
push rax
pop rdi
push 0x1010101 ^ 0x656563
xor dword ptr [rsp], 0x1010101
mov rax, 0x617274206d6f7266
push rax
mov rax, 0x2073692073696874
push rax
mov rsi, rsp
push 0x20
pop rdx
/* call write() */
push SYS_write /* 1 */
pop rax
syscall

mov rax, 0x3
syscall

add rsp, 0x28
pop r9
pop r8
pop r10
pop rdx
pop rsi
pop rdi
pop rax
syscall
cmp rax,0xfffffffffffff000
ret

nop
nop
nop
nop
nop
nop
nop
