# Cave Canem NIDS - Network Intrusion Detection System.
## Summary
Is a Linux kernel module used for track suspicious packet and implement some basic functionality as a Network Intrusion Detection System. Intercept all TCP SYN in, TCP SYN/ACK out and ICMP 8 incoming packet.
It use a device to exchange data from and to the user space that can be opened from any language. It is the rewrite of a very old module for the 2.6 linux and now can run into the current 4.x kernel version.
Especially today, create a kernel module to detect traffic it's not one of the best ideas ever! But could be an interesting way to learn how to develop a Linux kernel module and can be easily extended with a more useful Intrusion Prevention System functionality.

# How to install
As root.

Enable read/write permission to the device by creating a file in```/etc/udev/rules.d/666-cc_hooker.rules```
The write into the file this rules:

```
KERNEL=="cc_hooker", SUBSYSTEM=="cchlkm", MODE="0666"
```

Install:
```
make clean
make
insmod cc_hooker.ko
```

Chek if everythong is ok with
```
lsmod | grep cc_hooker
dmesg
```

## How to remove
```
rmmod cc_hooker
```

# Output example

from /dev:
```
ALERT-TCP-IN:127.0.0.1:666
ALERT-ICMP-IN:127.0.0.1:127.0.0.1
ALERT-ICMP-IN:127.0.0.1:127.0.0.1
ALERT-ICMP-IN:127.0.0.1:127.0.0.1
ALERT-ICMP-IN:127.0.0.1:127.0.0.1
ALERT-TCP-IN:172.16.110.1:22
ALERT-TCP-OUT:172.16.110.128:51216
ALERT-TCP-IN:172.16.110.1:11223
```

From Kernel messages:
```
[  274.997513] CC_Hooker: Initializing Cave-Canem_hooker LKM...
[  274.998466] CC_Hooker: Character Device created!(n: 244)
[  274.998470] CC_Hooker: Initialization in-out register hook.
[  294.824954] CC_Hooker: Device has been opened 
[  310.137175] CC_Hooker: [TCP_SYN-IN] packet <-- src ip: 127.0.0.1, src port: 47476; dest ip: 127.0.0.1, dest port: 666;
[  331.340450] CC_Hooker: [ICMP-IN] packet <-- from 127.0.0.1 to 127.0.0.1
[  331.340475] CC_Hooker: [ICMP-IN] packet <-- from 127.0.0.1 to 127.0.0.1
[  332.355969] CC_Hooker: [ICMP-IN] packet <-- from 127.0.0.1 to 127.0.0.1
[  332.356002] CC_Hooker: [ICMP-IN] packet <-- from 127.0.0.1 to 127.0.0.1
[  430.079045] CC_Hooker: [TCP_SYN-IN] packet <-- src ip: 172.16.110.1, src port: 51216; dest ip: 172.16.110.1, dest port: 22;
[  430.079148] CC_Hooker: [TCP_SYN_ACK-OUT] packet <--> src ip: 172.16.110.128, src port: 22; dest ip: 172.16.110.128, dest port: 51216;
[  462.160310] CC_Hooker: [TCP_SYN-IN] packet <-- src ip: 172.16.110.1, src port: 57720; dest ip: 172.16.110.1, dest port: 11223;
```

# Debuggging with GDB

First we need to compile and load the module
```
insmod cc_hooker.ko
```
Then we need the module's symbols to load into GDB. You can use objdump, or simply with a cat and get all the sections

```
cat /sys/module/cc_hooker/sections/.text 
0xffffffffc05d6000
```
```
cat /sys/module/cc_hooker/sections/.bss 
0xffffffffc05d8480
```

Take a look at the disassembled with objdump
```
objdump cc_hooker.ko -t
```
and find all the section and relative symbols that you need for debugging.

## GDB

Go to (root) / and run gdb loading linux kernle symbols
```
gdb vmlinux
```
Add the module's symbol to GDB

```
(gdb) add-symbol-file /pathto/cc_hooker.ko 0xffffffffc05d6000 -s .bss 0xffffffffc05d8480
add symbol table from file "/pathto/cc_hooker.ko" at
        .text_addr = 0xc05d6000
        .bss_addr = 0xc05d8480
(y or n) y
Reading symbols from /pathto/cc_hooker.ko...done.
```

Add breakpoints, unload and reload the module to intercept the function and have fun!
## Authors

* **Alessandro Bosco**

## License

This project is licensed under the GPLv3 - [www.gnu.org](http://www.gnu.org/licenses/)

## Acknowledgments

