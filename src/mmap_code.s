push rax
push rdi
push rsi
push rdx
push r10
push r8
push r9

mov rax, 0x9
mov rdi, 0x0
mov rsi, 0x1000
mov rdx, 0x5
mov r10, 0x22
mov r8, 0x0
mov r9, 0x0
syscall

pop rax
pop rdi
pop rsi
pop rdx
pop r10
pop r8
pop r9

nop
nop
nop
nop
nop
nop
nop
