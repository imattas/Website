# Kernel module Makefile
# Requires kernel headers: sudo apt install linux-headers-$(uname -r)

obj-m += flagcheck.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all: module userspace

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

userspace: test_module.c
	gcc -Wall -Wextra -o test_module test_module.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f test_module

# Quick setup: load module and create device node
load:
	sudo insmod flagcheck.ko
	@echo "Module loaded. Device at /dev/flagcheck"

unload:
	sudo rmmod flagcheck
	@echo "Module unloaded."

.PHONY: all module userspace clean load unload
