obj-m := buffer.o
BUILDROOT_PATH := /home/ptr/armoury/buildroot
CC := $(BUILDROOT_PATH)/output/host/bin/x86_64-linux-gcc
KBUILD_DIR := $(BUILDROOT_PATH)/output/build/linux-5.16.14

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

interface: interface.c
	$(CC) interface.c -o interface -pie

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
