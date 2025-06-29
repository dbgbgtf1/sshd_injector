#include "got_offset.h"
#include "inject_code.h"
#include "log.h"
#include "proc_map.h"
#include "seg_gap.h"
#include "trace_utils.h"

#include "assemble.h"
#include "sshd_accept.h"
#include "sshd_execve.h"
// clang-format off
#include <iso646.h>
#include <stdio.h>
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

int
main (int argc, char **argv)
{
  if (argc != 2)
    PEXIT ("usage: injector pid");
  uint32_t pid = strtol (argv[1], NULL, 0);

  attach (pid);
  // ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

  detach (pid);
}
