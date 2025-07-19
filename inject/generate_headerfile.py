from elftools.elf.elffile import ELFFile

def get_func_offset(func_name: str, elf_path: str) -> int:
    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if section.name in ('.dynsym', '.symtab'):
                    for symbol in section.iter_symbols():
                        if symbol.name == func_name:
                            return symbol['st_value']
    except Exception as e:
        print(f"[!] Error reading ELF file: {e}")
        return 0

    return 0

encode = b''
with open ('./build/sshd_execv_hook.bin', 'rb') as f:
    encode += f.read1()
c_asm = "".join([f"\\x{i:02x}" for i in encode])
execv_hook_offset = get_func_offset("execv_hook", "./build/sshd_execv_hook.o") - 0x1000

with open ('./sshd_execv_hook.h', 'w+') as res:
    res.write ('#ifndef SSHD_EXECV\n')
    res.write ('#define SSHD_EXECV\n\n')

    res.write (f'#include <stdint.h>\n')
    res.write (f'#define EXECV_HOOK_OFFSET {hex(execv_hook_offset)}\n')
    res.write (f'uint8_t sshd_execv[] = "{c_asm}";\n\n')

    res.write (f'#endif')

encode = b''
with open ('./build/sshd_accept_hook.bin', 'rb') as f:
    encode += f.read1()
c_asm = "".join([f"\\x{i:02x}" for i in encode])
accept_hook_offset = get_func_offset("accept_hook", "./build/sshd_accept_hook.o") - 0x1000

with open ('./sshd_accept_hook.h', 'w+') as res:
    res.write ('#ifndef SSHD_ACCEPT\n')
    res.write ('#define SSHD_ACCEPT\n\n')

    res.write (f'#include <stdint.h>\n')
    res.write (f'#define ACCEPT_HOOK_OFFSET {hex(accept_hook_offset)}\n')
    res.write (f'uint8_t sshd_accept[] = "{c_asm}";\n\n')

    res.write (f'#endif')
