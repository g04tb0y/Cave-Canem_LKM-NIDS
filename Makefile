obj-m += cc_hooker.o
ccflags-y := -Wall -Wno-incompatible-pointer-types
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
