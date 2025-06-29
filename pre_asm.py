from os import popen
from pwn import *

os.system("gcc -fno-asynchronous-unwind-tables -O1 sshd_execv_hook.c -masm=intel -nostdlib -ffreestanding -fno-stack-protector -fno-PIE -o sshd_execv_hook")
os.system("objcopy -O binary -j .text sshd_execv_hook sshd_execv_hook.bin")

encode = b''
with open ('./sshd_execv_hook.bin', 'rb') as f:
    encode += f.read1()
c_asm = "".join([f"\\x{i:02x}" for i in encode])

with open ('./include/sshd_execv_hook.h', 'w') as res:
    res.write ('#ifndef SSHD_EXECV\n')
    res.write ('#define SSHD_EXECV\n\n')

    res.write (f'char sshd_execv[] = "{c_asm}";\n\n')

    res.write (f'#endif')

os.system("gcc -fno-asynchronous-unwind-tables -O1 sshd_accept_hook.c -masm=intel -nostdlib -ffreestanding -fno-stack-protector -fno-PIE -o sshd_accept_hook")
os.system("objcopy -O binary -j .text sshd_accept_hook sshd_accept_hook.bin")

encode = b''
with open ('./sshd_accept_hook.bin', 'rb') as f:
    encode += f.read1()
c_asm = "".join([f"\\x{i:02x}" for i in encode])

with open ('./include/sshd_accept.h', 'w') as res:
    res.write ('#ifndef SSHD_ACCEPT\n')
    res.write ('#define SSHD_ACCEPT\n\n')

    res.write (f'char sshd_accept[] = "{c_asm}";\n\n')

    res.write (f'#endif')
