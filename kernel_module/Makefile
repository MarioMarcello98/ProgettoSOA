CC = gcc-13

obj-m += snapshot.o

snapshot-objs := snapshot_main.o utils.o

KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules CC=$(CC)

clean:
	make -C $(KDIR) M=$(PWD) clean
