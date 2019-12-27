AFL的链接https://lwn.net/Articles/657959/

syzkaller链接 https://lwn.net/Articles/677764/

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

syzkaller https://lwn.net/Articles/677764/
用户空间模糊测试
模糊测试的基本方法是大量生成随机的输入到程序中，然后观察程序的状态，但是这种方法仅仅盲目地生成随机数据，无法找到深层次的程序漏洞，效率十分低下。另一种模糊测试技术使用模板来生成合法输入来发现深层漏洞，针对每一种目标需要手动创建模板用于测试，需要要目标相关的领域知识。
最近出现了以覆盖率作为指导的模糊测试技术，比如Michał Zalewski写的American fuzzy lop AFL和clang的LibFuzzer，这些模糊测试技术不需要目标模板，而是使用二进制编译时插入的指令来获得运行时的覆盖信息，为获得更高的覆盖率，这些模糊测试技术会尽可能的扩大测试输入变异。同时这些模糊测试技术能够很好的与内存检测技术一同发现潜在的错误，比如ASAN、TSAN
syzkaller需要基于每个任务跟踪覆盖率数据，并将其从内核导出到外部，syzkaller使用的是/sys/kernel/debug/kcov，同时为了与内存检测工具一起配合，需要使用KASAN（kernel adddress sanitizer）打开。
syzkaller使用QEMU来运行已经编译好的内核，有内核系统中的syz-fuzzer和syz-executor来运行指定系统调用，然后使用/sys/kernel/debug/kcov来获得覆盖信息
对于不使用模拟的测试方法速度会很快，但是他们缺少对无源码系统的测试方法。
syzkaller创建x86_64内核测试环境 https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md

在Syzkaller之前的Trinity
while (true) syscall(rand(), rand(), rand());
在知道参数类型的时候：
while (true) syscall(rand(), rand_fd(), rand_addr());
只能找到浅层的漏洞

而Syzkaller是Coverage-guided grammar based kernel fuzzer

算法： 1.一开始是空的程序预料库 2.生成一个新的程序语料或者选择一个已有程序作为语料 3.运行程序，收集覆盖信息 4.如果新的代码被覆盖，最小化程序，然后添加至预料库


Skzkaller使用：
https://github.com/google/syzkaller/blob/master/docs/linux/setup.md
首先安装go语言
wget https://dl.google.com/go/go1.13.5.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.13.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
然后下载syzkaller，go get -u -d github.com/google/syzkaller/...
cd $HOME/go/src/github.com/google/syzkaller
make
生成的二进制程度在bin文件夹中

制作镜像
sudo apt-get install debootstrap
syzkaller/tools/create-images.sh

在使用tools/create-image.sh后会生成公钥私钥
mkdir ~/img
装载镜像 sudo mount -o loop stretch.img ~/img
将公钥拷贝 sudo cp stretch.id_rsa.pub ~/img/root
之后 ssh -p 10021 -i IMAGE/stretch.id_rsa root@127.0.0.1 就能免密码登录了
ss.cfg
{
 "target": "linux/amd64",
 "http": "127.0.0.1:10233",
 "workdir": "/home/ss/go/src/github.com/google/syzkaller/workdir",
 "kernel_obj": "/home/ss/linux",
 "image": "/home/ss/IMAGE/stretch.img",
 "sshkey": "/home/ss/IMAGE/stretch.id_rsa",
 "syzkaller": "/home/ss/go/src/github.com/google/syzkaller",
 "procs": 4,
 "type": "qemu",
 "vm": {
  "count": 4,
  "kernel": "/home/ss/linux/arch/x86_64/boot/bzImage",
  "cpu": 2,
  "mem": 2048
 }
}
需要将bin文件夹也拷贝到镜像stretch.img中
然后就能运行了sudo bin/syz-manager -config=ss.cfg

syzkaller的问题在于只模糊测试系统调用，而unicorefuzz也模糊测试内核所有代码，而且可以在任意位置运行

ip_output.c下的ip_do_fragment函数https://lkml.org/lkml/2018/8/9/799
在git checkout 112cbae26d18的源码后编译运行，使用方法https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md
需要注意的是不要启用KCOV、KASAN
启用CONFIG_DEBUG_INFO=y，然后在make oldconfig时，启用gdb python script
在create_image.sh中修改printf '\nauto eth0\niface eth0 inet dhcp\n\nauto enp0s3\niface enp0s3 inet dhcp\n' | sudo tee -a $DIR/etc/network/interfaces

在启动linux是会出现
[FAILED] Failed to mount /sys/kernel/config.
You are in emergency mode. After logging in, type "journalctl -xb" to view
system logs, "systemctl reboot" to reboot, "systemctl default" or ^D to
try again to boot into default mode.
修改.config
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
然后再make -j12
因为configfs用于提供基于ram的虚拟文件系统，与sysfs类似，用于在用户空间管理创建内核对象，常挂载到/sys/kernel/config

然后使用qemu运行
#!/bin/sh
stty intr ^]
echo "[*] ctrl+c remapped to ctrl+] for host"
KERNEL=/home/ss/linux
IMG=/home/ss/IMAGE
/home/ss/qemu-4.2.0/x86_64-softmmu/qemu-system-x86_64 \
  -hda $IMG/stretch.img \
	-net nic -net user,hostfwd=tcp::8022-:22 \
	-m 4096 \
	-smp 1 \
	-s \
	-append "root=/dev/sda console=ttyS0 debug nokaslr quiet" \
	-serial stdio \
	-enable-kvm \
	-display none \
  -kernel $KERNEL/arch/x86_64/boot/bzImage

在linux源码目录下输入gdb vmlinux
break ip_do_fragment
continue
然后在虚拟机需要ping 192.168.1.1 -s 3000
这个函数主要是用于IP数据报太大了，无法在一片中发送，需要将其切分为更小的片段（每一个大小相当于IP头部加原来数据的一部分），使其符合设备帧大小，然后将这些帧放入队列中等待发送
sk_buff {
    struct {
        struct sk_buff *next;  链表中下一个buffer
        struct sk_buff *prev;  链表中上一个buffer
        union {
			struct net_device	*dev;  到达/离开所用的设备
			unsigned long		dev_scratch;
			int			ip_defrag_offset;
		};
    }
    struct sock *sk;     归属的socket
    ktime_t tstamp;      到达/离开的时间
    char cb[48] __aligned(8);   控制块，存放私有信息
    union {
		struct {
			unsigned long	_skb_refdst;  目的条目
			void		(*destructor)(struct sk_buff *skb);
		};
		struct list_head	tcp_tsorted_anchor;
	};
    unsigned int	len,  实际数据长度，包括各个片段大小
				    data_len; 数据长度，当前片段的大小
	__u16			mac_len,  链路层大小
				    hdr_len;  cloned skb的可写头部长度
    __u16			queue_mapping;
    	__u8			__cloned_offset[0];
	__u8			cloned:1,  头部是否被克隆
				    nohdr:1,   负载引用
				    fclone:2,  skbuff的clone状态
				    peeked:1,  这个数据包已经准备好了
				    head_frag:1,
				    xmit_more:1,
				    pfmemalloc:1;
    __u32			headers_start[0];
    __u8			__pkt_type_offset[0];
	__u8			pkt_type:3;  Packet类型
	__u8			ignore_df:1;  允许本地分段 allow local fragmentation
	__u8			nf_trace:1;   netfiler包追踪标志位
	__u8			ip_summed:2;  驱动提供的IP校验和
	__u8			ooo_okay:1;

	__u8			l4_hash:1;
	__u8			sw_hash:1;
	__u8			wifi_acked_valid:1;
	__u8			wifi_acked:1;
	__u8			no_fcs:1;

	__u8			encapsulation:1;
	__u8			encap_hdr_csum:1;
	__u8			csum_valid:1;

	__u8			csum_complete_sw:1;
	__u8			csum_level:2;
	__u8			csum_not_inet:1;
	__u8			dst_pending_confirm:1;
    
    __u8			ipvs_property:1;

	__u8			inner_protocol_type:1;
	__u8			remcsum_offload:1;

    union {
		__wsum		csum;  校验和
		struct {
			__u16	csum_start;  从skb->head开始的偏移，从这里开始进行校验和计算
			__u16	csum_offset; 从csum_start开始计算的偏移，在这里存放checksum
		};
	};
	__u32			priority;  数据包排队优先级
	int			    skb_iif;
	__u32			hash;
	__be16			vlan_proto;
	__u16			vlan_tci;

    union {
		__u32		mark;
		__u32		reserved_tailroom;
	};
    union {
		__be16		inner_protocol;  Protocol (encapsulation)
		__u8		inner_ipproto;
	};

	__u16			inner_transport_header; 传输层头部
	__u16			inner_network_header;  网络层头部
	__u16			inner_mac_header;  链路层头部

	__be16			protocol;  驱动提供的数据包协议
	__u16			transport_header;
	__u16			network_header;
	__u16			mac_header;

	/* private: */
	__u32			headers_end[0];
    sk_buff_data_t		tail;  尾部指针
	sk_buff_data_t		end;
	unsigned char		*head,  buffer头部指针
				*data;    数据头部指针
	unsigned int		truesize;  buffer大小
	refcount_t		users;   用户数量
}
可以确定data的位置
sk_buff的图示https://www.cnblogs.com/qq78292959/archive/2012/06/06/2538358.html

在ip_finish_output中会因为数据包大于链路mtu，进入ip_fragment分片，如果ip中支持分片（没有设置don't fragment标志位），那么进入ip_do_fragment进行分片

linux源码阅读vscode配置，https://jekton.github.io/2018/05/11/how-to-read-android-source-code/

在include/linux/skbuff.h中定义了对sk_buff结构的操作
net/core/skbuff.c定义的skb_copy_bits将字节从skbuffer拷贝到内核buffer



