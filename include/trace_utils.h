#ifndef TRACE
#define TRACE

// clang-format off
#include <stddef.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/user.h>
// clang-format on

#define TRACE_POKEDATA "trace pokedata"
#define TRACE_PEEKDATA "trace peekdata"
#define TRACE_GETREGS "trace get regs"
#define TRACE_SETREGS "trace set regs"
#define TRACE_ATTACH "trace attach"
#define TRACE_DETACH "trace detach"
#define TRACE_STEP "trace step"
#define TRACE_SYSCALL "trace syscall"
#define WAIT_ERR "wait"
#define TRACE_GET_SYSCALL_INFO "trace get syscall info"

void copy_to_traee (uint32_t pid, size_t addr, char *data, uint32_t len);

void copy_from_tracee (uint32_t pid, size_t addr, char *data, uint32_t len);

void get_regs (uint32_t pid, struct user_regs_struct *regs);

void set_regs (uint32_t pid, struct user_regs_struct *regs);

void attach (uint32_t pid);

void detach (uint32_t pid);

void next_step (uint32_t pid);

void next_syscall (uint32_t pid);

void get_syscall_info (uint32_t pid, struct ptrace_syscall_info *info);

size_t break_at_sys_nr (uint32_t pid, uint32_t syscall_nr);

#endif
