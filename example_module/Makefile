obj-m += procfs1.o

all:
	make -C /home/ss/linux-5.2.21 M=$(PWD) modules
clean:
    rm -rf .tmp_versions
    rm *.cmd *.o *.ko
