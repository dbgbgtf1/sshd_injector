# sshd_injector
A stupid and undone tools to inject some system proc

## idea

现在实现方法是这样的，劫持master进程的accept，根据端口规则进行过滤以及隐藏  
除了划圈的return，其余一律再次关闭后门  
也就是说，只有当先以5端口连接，再立刻以39030端口连接才能触发后门  
这两个连接在sshd的处理必须连续，如果中间被插队了也不行

![image](https://github.com/user-attachments/assets/347a45ad-d54c-482a-899f-32f2a3b4b030)
