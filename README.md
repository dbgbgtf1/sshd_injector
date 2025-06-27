# sshd_injector
A stupid and undone tools to inject some system proc

## idea

现在实现方法是这样的，劫持master进程的accept，根据端口规则进行过滤以及隐藏  
除了划圈的return，其余一律再次关闭后门  
也就是说，只有当先以5端口连接，再立刻以39030端口连接才能触发后门  
这两个连接在sshd的处理必须连续，如果中间被插队了也不行

![image](https://github.com/user-attachments/assets/347a45ad-d54c-482a-899f-32f2a3b4b030)

## TODO

还有一些想完善的地方

- 目前后门的形式不是很完美，因为后门是简单的fork一个进程，重定向后执行bash  
    原进程会认为accept失败返回了错误值，尽管设置了合理的errno使得该错误不被记录
    但是从pstree上看到的结构并不合理，可以看到合法的ssh连接比较复杂，而后门仅仅是一个bash，有些不够隐蔽
```
        ├─sshd─┬─bash
        │      └─sshd-session───sshd-session───zsh
```

- 目前对于sshd的段解析和got表依赖pwntools完成，比较麻烦，后期想办法把解析合并到c程序，运行时解析

- bash的重定向最好要有加密，否则在流量上也容易引起怀疑

- 还有就是没有考虑到可能需要重复注入，目前想要重新注入只能重启sshd服务

总的来说，上面这些东西想通过再注入sshd-session来解决
