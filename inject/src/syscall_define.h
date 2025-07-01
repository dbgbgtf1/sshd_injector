#include <stdint.h>

#define REGISTERS_CLOBBERED_BY_SYSCALL                                        \
  "cc", "r11",                                                                \
      "cx"                                                                    \
      "memory"

// syscall0 - 0参数
inline uint64_t
syscall0 (uint64_t num)
{
  uint64_t ret;

  register uint64_t rax __asm__ ("rax") = num;

  __asm__ volatile ("syscall" : "=a"(ret) : "a"(rax) : "rcx", "r11", "memory");
  return ret;
}

// syscall1 - 1参数
inline uint64_t
syscall1 (uint64_t num, uint64_t arg1)
{
  uint64_t ret;

  register uint64_t rax __asm__ ("rax") = num;
  register uint64_t rdi __asm__ ("rdi") = arg1;

  __asm__ volatile ("syscall" : "=a"(ret) : "a"(rax), "r"(rdi) : "rcx", "r11", "memory");

  return ret;
}

// syscall2 - 2参数
inline uint64_t
syscall2 (uint64_t num, uint64_t arg1, uint64_t arg2)
{
  uint64_t ret;

  register uint64_t rax __asm__ ("rax") = num;
  register uint64_t rdi __asm__ ("rdi") = arg1;
  register uint64_t rsi __asm__ ("rsi") = arg2;

  __asm__ volatile ("syscall" : "=a"(ret) : "a"(rax), "r"(rdi), "r"(rsi) : "rcx", "r11", "memory");

  return ret;
}

// syscall3 - 3参数
inline uint64_t
syscall3 (uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
  uint64_t ret;

  register uint64_t rax __asm__ ("rax") = num;
  register uint64_t rdi __asm__ ("rdi") = arg1;
  register uint64_t rsi __asm__ ("rsi") = arg2;
  register uint64_t rdx __asm__ ("rdx") = arg3;

  __asm__ volatile ("syscall" : "=a"(ret) : "a"(rax), "r"(rdi), "r"(rsi), "r"(rdx) : "rcx", "r11", "memory");

  return ret;
}

// syscall4 - 4参数
inline uint64_t
syscall4 (uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3,
          uint64_t arg4)
{
  uint64_t ret;

  register uint64_t rax __asm__ ("rax") = num;
  register uint64_t rdi __asm__ ("rdi") = arg1;
  register uint64_t rsi __asm__ ("rsi") = arg2;
  register uint64_t rdx __asm__ ("rdx") = arg3;
  register uint64_t r10 __asm__ ("r10") = arg4;

  __asm__ volatile ("syscall" : "=a"(ret) : "a"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10) : "rcx", "r11", "memory");

  return ret;
}

// syscall5 - 5参数
inline uint64_t
syscall5 (uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3,
          uint64_t arg4, uint64_t arg5)
{
  uint64_t ret;

  register uint64_t rax __asm__ ("rax") = num;
  register uint64_t rdi __asm__ ("rdi") = arg1;
  register uint64_t rsi __asm__ ("rsi") = arg2;
  register uint64_t rdx __asm__ ("rdx") = arg3;
  register uint64_t r10 __asm__ ("r10") = arg4;
  register uint64_t r8 __asm__ ("r8") = arg5;

  __asm__ volatile ("syscall" : "=a"(ret) : "a"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8) : "rcx", "r11", "memory");

  return ret;
}

// syscall6 - 6参数
inline uint64_t
syscall6 (uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3,
          uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
  uint64_t ret;

  register uint64_t rax __asm__ ("rax") = num;
  register uint64_t rdi __asm__ ("rdi") = arg1;
  register uint64_t rsi __asm__ ("rsi") = arg2;
  register uint64_t rdx __asm__ ("rdx") = arg3;
  register uint64_t r10 __asm__ ("r10") = arg4;
  register uint64_t r8 __asm__ ("r8") = arg5;
  register uint64_t r9 __asm__ ("r9") = arg6;

  __asm__ volatile ("syscall" : "=a"(ret) : "a"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");

  return ret;
}
