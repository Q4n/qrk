# qrk

Q4n's lkm rootkit

Linux q4n 5.8.0-48-generic #54~20.04.1-Ubuntu SMP Sat Mar 20 13:40:25 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

只在当前版本测试, 内核不同版本间api有改动, hook的函数和方式有所改变



## build

### 编译&安装

`make && make install`

### 交互

`sudo python3 client.py `

依赖scapy



## 特征

- [x] ### 权限提升

通过hook SYS_open进行后门操作

open(cmd, cmd_length, 0xdeadbeef)

 

- [x] ### 隐藏文件和目录

隐藏/恢复

内容隐藏, 目录结构隐藏

两种实现:

​	vfs hook

​	hook syscall

这里用的是hook vfs



pid隐藏就是隐藏 /proc中内容

还需要实现隐藏 /sys 和 /

- [x] ### 隐藏进程

隐藏/恢复

通过hide /proc/pid 来隐藏



- [x] ### 隐藏自己

隐藏/恢复

- lsmod

- /sys/module/qrk

- /proc/kallsym



/var/log/syslog.1, 这个应该是crash后才有的, 不需要理会

/var/log/kern.log 需要删除



未解决(暂时的想法是将模块重命名 《瞒天过海》):

/sys/kernel/tracing/available_filter_functions 

/sys/kernel/debug/kprobes/blacklist

/sys/kernel/debug/tracing/available_filter_functions 

/lib/modules/5.8.0-48-generic/modules.dep



mokutil 驱动签名校验, 但是这里需要重启才能生效



- [x] ### 卸载保护

隐藏/恢复

- [ ] ### 代码混淆

汇编层面混淆, 以后再写， 可能只能实现x86的， x64的暂时没有发现

- [x] ### 开机启动

隐藏启动脚本

必须从shell脚本运行

1. 将。ko复制到 路径

2. /etc/init.d/e1000x 启动脚本

    （貌似不能成功加载）



 	1. `/lib/modules/$(KERNEL)/kernel/drivers/​$(DRIVER)`放入.ko
 	2. `/etc/modules-load.d/$(DRIVER).conf` 写入 qrk
 	3. 执行depmod



- [x] ### icmp(/tcp/udp)后门

icmp 命令执行(未加密)

netfilter hook实现

- [x] ### 隐藏socket连接

隐藏/恢复 通信端口, 是针对双方的



## others

新版本中引入

​	asmlinkage long (*sys_getdents)(struct pt_regs *regs);



## 参考的repo

lkm-rootkit

reptile

rkduck

rootkit

suterusu

