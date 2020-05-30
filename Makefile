obj-m := chris.o
chris-objs := main.o dev.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

#PWD       := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) clean
	