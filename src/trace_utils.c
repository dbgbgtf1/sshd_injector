#include "trace_utils.h"
#include "log.h"
#include <linux/ptrace.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

void
copy_to_tracee (uint32_t pid, uint64_t addr, uint8_t *data, uint32_t len)
{
  uint64_t ptr = 0;

  while (ptr < len)
    {
      uint64_t data_cur = ((uint64_t *)data)[ptr / sizeof (uint64_t)];
      if (ptrace (PTRACE_POKETEXT, pid, addr + ptr, data_cur) == -1)
        PERROR (TRACE_POKEDATA);
      ptr += 8;
    }
}

void
copy_from_tracee (uint32_t pid, uint64_t addr, char *data, uint32_t len)
{
  uint64_t ptr = 0;

  while (ptr < len)
    {
      uint64_t data_cur = ptrace (PTRACE_PEEKTEXT, pid, addr + ptr, NULL);
      ((uint64_t *)data)[ptr / sizeof (uint64_t)] = data_cur;
      ptr += 8;
    }
}

void
get_regs (uint32_t pid, struct user_regs_struct *regs)
{
  if (ptrace (PTRACE_GETREGS, pid, NULL, regs) == -1)
    PERROR (TRACE_GETREGS);
}

void
set_regs (uint32_t pid, struct user_regs_struct *regs)
{
  if (ptrace (PTRACE_SETREGS, pid, NULL, regs) == -1)
    PERROR (TRACE_SETREGS);
}

void
attach (uint32_t pid)
{
  if (ptrace (PTRACE_ATTACH, pid, NULL, NULL) == -1)
    PERROR (TRACE_ATTACH);
  if (wait (NULL) == -1)
    PERROR (WAIT_ERR);
}

void
detach (uint32_t pid)
{
  if (ptrace (PTRACE_DETACH, pid, NULL, NULL) == -1)
    PERROR (TRACE_DETACH);
}

void
next_step (uint32_t pid)
{
  if (ptrace (PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
    PERROR (TRACE_STEP);
  if (wait (NULL) == -1)
    PERROR (WAIT_ERR);
}

void
next_syscall (uint32_t pid)
{
  if (ptrace (PTRACE_SYSCALL, pid, NULL, NULL) == -1)
    PERROR (TRACE_SYSCALL);
  if (wait (NULL) == -1)
    PERROR (WAIT_ERR);
}

void
get_syscall_info (uint32_t pid, struct ptrace_syscall_info *info)
{
  if (ptrace (PTRACE_GET_SYSCALL_INFO, pid,
              sizeof (struct ptrace_syscall_info), info)
      == -1)
    PERROR (TRACE_GET_SYSCALL_INFO);
}

uint64_t
break_at_sys_nr (uint32_t pid, uint32_t syscall_nr)
{
  struct ptrace_syscall_info info;

  while (true)
    {
      next_syscall (pid);
      get_syscall_info (pid, &info);
      if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == syscall_nr)
        break;
    }

  next_syscall (pid);
  get_syscall_info (pid, &info);

  if (info.exit.rval < 0)
    {
      printf ("tracee sys_nr %d failed\n", syscall_nr);
      exit (0);
    }

  return info.exit.rval;
}
