#include "log.h"
#include "mmap_code.h"
#include "shell_code.h"
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
// clang-format on

#define PADDING 0x10

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

typedef struct
{
  size_t addr;
  void *restore_code;
  uint32_t len;
} restore_text;

restore_text restore_pages[10] = { 0 };

uint32_t
inject_code_and_restore (uint32_t pid, size_t addr, char *unpadded_code)
{
  uint32_t idx = -1;

  for (uint32_t i = 0; i < 10; i++)
    {
      if (restore_pages[i].len == 0)
        {
          idx = i;
          break;
        }
    }
  if (idx == (uint32_t)-1)
    PEXIT ("not enough space")

  uint32_t len = sizeof (mmap_code) - 1;
  char *padded_code = code_padding (unpadded_code, &len);
  char *restore_code = malloc (len);

  copy_from_tracee (pid, addr, restore_code, len);
  copy_to_traee (pid, addr, padded_code, len);
  // free (padded_code);

  restore_pages[idx].len = len;
  restore_pages[idx].addr = addr;
  restore_pages[idx].restore_code = restore_code;

  return idx;
}

void
restore_with_idx (uint32_t pid, uint32_t idx)
{
  copy_to_traee (pid, restore_pages[idx].addr, restore_pages[idx].restore_code,
                 restore_pages[idx].len);
  free (restore_pages[idx].restore_code);
  restore_pages[idx].restore_code = 0;
}

void
inject_code (uint32_t pid, size_t addr, char *unpadded_code)
{
  uint32_t len = sizeof (shell_code) - 1;
  char *padded_code = code_padding (unpadded_code, &len);

  copy_to_traee (pid, addr, padded_code, len);
  // free (padded_code);
}

void
at_syscall (uint32_t pid)
{
  struct user_regs_struct regs;
  get_regs (pid, &regs);

  size_t origin_rip = regs.rip;
  regs.rip &= ~0xfff;
  uint32_t idx = inject_code_and_restore (pid, regs.rip, mmap_code);

  regs.rip += 2;
  set_regs (pid, &regs);
  // set rip, jmp to the start of page

  size_t rax = break_at_sys_nr (pid, 0x9);
  // break at mmap, rax is the text addr

  inject_code (pid, rax, shell_code);
  // inject code into rax

  break_at_sys_nr (pid, 0xa);
  // break at mprotect

  for (uint32_t i = 0; i < 7; i++)
    next_step (pid);
  regs.rip = rax;
  set_regs (pid, &regs);
  // set rip, jmp to mmap text

  restore_with_idx (pid, idx);
  // so we can restore the text now

  get_regs (pid, &regs);
  // get rsp

  regs.rsp -= sizeof (size_t);
  set_regs (pid, &regs);
  // push origin_rip

  get_regs (pid, &regs);
  origin_rip += 8;
  copy_to_traee (pid, regs.rsp, (char *)&origin_rip, sizeof (size_t));
  // push origin_rip, origin_rip will be the return addr

  size_t modify_rip = origin_rip - 0x10;
  origin_rip -= 8;
  uint8_t origin_code[0x10];
  copy_from_tracee (pid, modify_rip, (char *)&origin_code, 0x10);
  origin_code[0x6 + 0] = '\xe8';
  origin_code[0x6 + 1] = (rax - origin_rip - 3) & 0xff;
  origin_code[0x6 + 2] = ((rax - origin_rip - 3) & 0xff00) >> 0x8;
  origin_code[0x6 + 3] = ((rax - origin_rip - 3) & 0xff0000) >> 0x10;
  origin_code[0x6 + 4] = '\x00';
  origin_code[0x6 + 5] = '\x90';
  origin_code[0x6 + 6] = '\x90';
  origin_code[0x6 + 7] = '\x90';
  copy_to_traee (pid, modify_rip, (char *)&origin_code, 0x10);
}

int
main (int argc, char **argv)
{
  if (argc != 2)
    PEXIT ("usage: injector pid");
  uint32_t pid = strtol (argv[1], NULL, 0);

  attach (pid);
  ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

  struct ptrace_syscall_info info;
  while (true)
    {
      next_syscall (pid);
      get_syscall_info (pid, &info);
      if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == 0x38)
        break;
    }
  // now we are before clone syscall

  at_syscall (pid);

  detach (pid);
}
