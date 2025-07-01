encode = b''
with open ('./build/sshd_execv_hook.bin', 'rb') as f:
    encode += f.read1()
c_asm = "".join([f"\\x{i:02x}" for i in encode])

with open ('./sshd_execv_hook.h', 'w+') as res:
    res.write ('#ifndef SSHD_EXECV\n')
    res.write ('#define SSHD_EXECV\n\n')

    res.write (f'#include <stdint.h>\n')
    res.write (f'uint8_t sshd_execv[] = "{c_asm}";\n\n')

    res.write (f'#endif')

encode = b''
with open ('./build/sshd_accept_hook.bin', 'rb') as f:
    encode += f.read1()
c_asm = "".join([f"\\x{i:02x}" for i in encode])

with open ('./sshd_accept_hook.h', 'w+') as res:
    res.write ('#ifndef SSHD_ACCEPT\n')
    res.write ('#define SSHD_ACCEPT\n\n')

    res.write (f'#include <stdint.h>\n')
    res.write (f'uint8_t sshd_accept[] = "{c_asm}";\n\n')

    res.write (f'#endif')
