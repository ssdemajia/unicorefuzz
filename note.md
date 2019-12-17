使用buildroot来构建 参考https://medium.com/@daeseok.youn/prepare-the-environment-for-developing-linux-kernel-with-qemu-c55e37ba8ade
构建后需要使用
配置buildroot，添加sudo软件


创建用户"ss"
adduser ss

a) 切换至root账户，为sudo文件增加写权限，默认是读权限
chmod u+w /etc/sudoers

b) 打开文件vim /etc/suduers，在root ALL=(ALL) ALL这一行下面添加
ss ALL=(ALL) ALL

需要将编译好的模块，放入挂载点
sudo cp example_module/procfs1.ko ~/img
然后在虚拟机中的/etc/init.d/rcS中添加一行insmod /procfs1.ko这样就能在开机时加载模块了
之后在虚拟机中/etc/init.d/S40network中添加一行udhcpc来获取ip地址https://github.com/OP-TEE/build/issues/103

如何获得模块代码段地址https://stackoverflow.com/questions/6384605/how-to-get-the-address-of-a-kernel-module-that-was-inserted-using-insmod

在linux4级页表中linux module所在内存地址范围https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt

Linux模块与普通程序的不同 http://tldp.org/LDP/lkmpg/2.6/html/x427.html
A program usually begins with a main() function, executes a bunch of instructions and terminates upon completion of those instructions. Kernel modules work a bit differently. A module always begin with either the init_module or the function you specify with module_init call. This is the entry function for modules; it tells the kernel what functionality the module provides and sets up the kernel to run the module's functions when they're needed. Once it does this, entry function returns and the module does nothing until the kernel wants to do something with the code that the module provides.

调试kernel module https://medium.com/@navaneethrvce/debugging-your-linux-kernel-module-21bf8a8728ba

linux kernel被加载到固定的地址后，可以通过readelf -s procfs1.ko查看函数的在ko中的偏移，以及该函数的代码长度

avatar获取fs_base和gs_base会有问题 // todo

x64参数传递http://abcdxyzk.github.io/blog/2012/11/23/assembly-args/
参数个数大于 7 个的时候
H(a, b, c, d, e, f, g, h);
a->%rdi, b->%rsi, c->%rdx, d->%rcx, e->%r8, f->%r9
h->8(%esp)
g->(%esp)

在x64体系结构中FS寄存器与GS寄存器与GDT无关，他们的基值保存在MSR寄存器中

ubuntu apt安装的qemu版本
➜  ~ qemu-system-x86_64 --version
QEMU emulator version 2.11.1(Debian 1:2.11+dfsg-1ubuntu7.21)
Copyright (c) 2003-2017 Fabrice Bellard and the QEMU Project developers

源码安装qemu
wget https://download.qemu.org/qemu-4.2.0.tar.xz
sudo apt install -y libsdl2-dev build-essential zlib1g-dev pkg-config libglib2.0-dev binutils-dev libboost-all-dev autoconf libtool libssl-dev libpixman-1-dev libpython-dev python-pip python-capstone virtualenv
./configure --target-list=x86_64-softmmu --enable-sdl