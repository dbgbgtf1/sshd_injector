catch syscall clone
c
si
set follow-fork-mode parent
b _start
c
c
delete breakpoints
b mm_answer_keyallowed
c
catch syscall openat
