b _start
c
c
b mm_answer_keyallowed
set follow-fork-mode parent
c
catch syscall openat
c
c
c
c
c
c
c
c
c
c

delete breakpoints
catch syscall read
c
c
set *(char *)$rsi='s'
#
# delete breakpoints
# catch syscall openat
# c
# c
#
# delete breakpoints
# catch syscall read
# c
# c
# set *(char *)$rsi='s'
