---
title: q-escape - SECCON 2018
date: '2018-11-22 22:12:08'
layout: post
---

> We developed a new device named CYDF :) Ubuntu 16.04 latest nc q-escape.pwn.seccon.jp 1337


*494 Pts, 2 solved, pwn. [q-escape.tar.gz](https://score-quals.seccon.jp/files/3cb6e98780efce70cf1d8606cb579ecd/q-escape.tar.gz_48901602a841daf68b60926a26efd4a80ad66c4c)*


We're given a qemu binary that has been compiled with a new device called `cydf` which looks like it is a vga device. After a bit of digging it seems to be a copy and paste of an existing qemu device [cirrus](https://github.com/qemu/qemu/blob/master/hw/display/cirrus_vga.c) which is also missing from the binary, a great place to start as it hopefully means that we have most of the source and just need to find what was added or changed.

Looking at the `CydfVGAState` structure we can see that there is a field called `VulnState vs[0x10];` that has been added, and it's name is a pretty big hint that we should focus on it. There is also a global which looks suspicious `0x10C94E0 ; uint64_t vulncnt`

The xrefs for `vulncnt` show that it is used in `cydf_vga_mem_write` and after a bit of RE we see that there are a couple of operations that we can perform based on the value of `s->vga.sr[0xCC]` if we use an `addr` greated than 0x10000 and less than 0x18000.

I didn't know too much about how to even access vga memory or the ioports, so some research was required. The source for the cirrus device had a [nice header](https://github.com/qemu/qemu/blob/master/hw/display/cirrus_vga.c#L2004) for `cirrus_vga_mem_read` saying `memory access between 0xa0000-0xbffff` which aligns with what [wikipedia says](https://en.wikipedia.org/wiki/Video_Graphics_Array#Addressing_details) for vga mappings. The other [hint in the original source](https://github.com/qemu/qemu/blob/master/hw/display/cirrus_vga.c#L2894) is in `cirrus_init_common` where is says `Register ioport 0x3b0 - 0x3df` and looking at the same functions in our binary the values line up.

An easy way of accessing the physical memory is to map `/dev/mem` into our process and then we can read/write to it like normal. The base image we are provided with does not have this mounted, but we can mount it with `mknod -m 660 /dev/mem c 1 1`. This allows us to do the following to access `0xa0000` directly:

```c
int fd = open("/dev/mem", O_RDWR | O_SYNC);
uint8_t *mem = mmap(0, 0x20000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0xa0000);
mem[0] = 0x41;
```

We can test this by setting a breakpoint on `cydf_vga_mem_write` to check that it gets called:
![breakpoint](/assets/seccon18/break.jpg)

The next issue is the function immediately returns due to the following check:
```c
if (!(s->vga.sr[7] & 1)) {
  vga_mem_writeb(&s->vga, addr, mem_value);
  return;
}
```

So we need to figure out how to set the value of `s->vga.sr[7]` to 1. There is a method called `cirrus_vga_write_sr` which looks like it's what we want, it allows you to do `s->vga.sr[s->vga.sr_index] = val;` so now we need to find out how to set `s->vga.sr_index`. This is done in [cirrus_vga_ioport_write](https://github.com/qemu/qemu/blob/master/hw/display/cirrus_vga.c#L2649) using ioport `0x3c4`, and we see directly below that ioport `0x3c5` is used to call `cirrus_vga_write_sr`.

To use the ioports we can use the following code:
```c
ioperm(0x3C4, 2, 1); // set port access
outb(7, 0x3C4);	// set the index
outb(1, 0x3C5); //set the sr value
```

By setting a breakpoint at `0x68F7C0` we can confirm that we are hitting the expected path:
![breakpoint](/assets/seccon18/ioport.jpg)


We should now be able to hit the section of code that deals with `VulnState` by setting  `s->vga.sr[7]` and accessing `addr` at 0x10000, and by setting a breakpoint at `0x68F27B` we can confirm this works!

```c
int fd = open("/dev/mem", O_RDWR | O_SYNC);
uint8_t *mem = mmap(0, 0x20000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0xa0000);
ioperm(0x3C4, 2, 1); // set port access
outb(7, 0x3C4);	// set the index
outb(1, 0x3C5); //set the sr value
mem[0x10000] = 0;
```

The disassembly for `cydf_vga_mem_write` looks like there are 5 different paths we can take based on the value of `s->vga.sr[0xCC]` (which we know how to set now) and they are create, write, print, update size, and another update. Later on I found that the last path had been removed from the server as they were running a different binary than the supplied one.

There is an obvious heap overflow as we can update the `max_size` and no realloc occurs, and the is also an off-by-one error that allows us to access `vs[0x10]` which actually points to a field called `latch`. If we can set this value then we have an easy read/write primative!

The latch gets set in `cydf_vga_mem_read` by either setting the lower 16 bits if they are 0, otherwise setting the upper 16 bits and clearing the lower 16.


```c
uint32_t latch = s->latch[0];
if (!(latch & 0xffff)) {
  s->latch[0] = addr | latch;
} else {
  s->latch[0] = addr << 16;
}
```

This is fine for us, we can set the latch in two goes, then read and write to it using the `vs[0x10]` bug. I choose to set it to the `__printf_chk` GOT at `0xEE7028` as it's easy to call.

When calling the print method for a `VulnState` it will print from the qemu process, so we need to read it with our wrapper (eg pwntools script) and then send the leak back into our exploit to set it.

Another catch was that `stdout` was line buffered, so to get any output you needed to print a newline to flush it.

All this worked locally and managed to use a magic gadget to get a shell, party time! But as is always the case, it didn't work remotely :( After some investigation I found that the remote binary wasn't just slightly different, the offsets were totally different and `0xEE7028` wasn't even mapped! I could still leak `ELF` from `0x400001` so hopefully it was just a matter of locating the GOT and the `__printf_chk` entry.

I leaked the PHT entry at `0x400130` to get the offset for the `_DYNAMIC` section, which let me know that the `GOT` started at `0xDEA000`. I then iterated through the entries until I found an address that would give me a libc base that ended in `000` which was found at `0xDEA2D8` and the rest of the exploit worked as intended!

`SECCON{6767ac011b200bde1249d241b1cd5480}`

[Full exploit](https://github.com/vakzz/ctfs/tree/master/Seccon2018/q-escape)

