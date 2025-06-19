from pwn import *
context.arch = 'amd64'

filename = "./src/" + sys.argv[1] + "_code.s"
with open(filename, 'r') as f:
    text = f.read()

print (text)

filename = "./include/" + sys.argv[1] + "_code.h"
with open(filename, 'w') as f:
    raw_asm = asm (text)
    f.write(f'#ifndef {sys.argv[1].upper() + "_CODE"}\n')
    f.write(f'#define {sys.argv[1].upper() + "_CODE"}\n\n')
    c_code = ''.join(f'\\x{b:02x}' for b in raw_asm)
    f.write(f'char {sys.argv[1] + "_code"}[] = "{c_code}";\n\n')
    f.write('#endif')
