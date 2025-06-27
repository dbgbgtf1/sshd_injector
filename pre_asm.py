c_asm = ""

with open ('./include/sshd_accept.s', 'r') as src:
    with open ('./include/sshd_accept.h', 'w') as res:
        line = src.readline().replace ('\n', ';')
        while line:
            c_asm += line
            line = src.readline ().replace ('\n', ';')

        res.write ('#ifndef SSHD_SCCEPT\n')
        res.write ('#define SSHD_SCCEPT\n\n')

        res.write (f'char sshd_accept[] = "{c_asm}";\n\n')

        res.write (f'#endif')

c_asm = ""
line = ""

with open ('./include/sshd_execve.s', 'r') as src:
    with open ('./include/sshd_execve.h', 'w') as res:
        pid = "4"
        map_str = "8"
        session_elf_base = "8"
        code_start = "0x10"
        line = src.readline().replace ('\n', ';')
        while line:
            c_asm += line
            line = src.readline ().replace ('\n', ';')
            if line.startswith ('//'):
                line = ";"
            line = line.format_map (locals ())

        res.write ('#ifndef SSHD_EXECVE\n')
        res.write ('#define SSHD_EXECVE\n\n')

        res.write (f'char sshd_execve[] = "{c_asm}";\n\n')

        res.write (f'#endif')

