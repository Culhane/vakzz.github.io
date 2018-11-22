---
title: internet_of_seat - SECCON 2018
date: '2018-11-22 21:15:49'
layout: post
---

> Who doesn't love IoT? Based on real life. Flag is on /flag.txt . (QEMU running on Ubuntu 16.04 latest for setting environment)
> 
> nc internet-of-seat.pwn.seccon.jp 1337


*500 Pts, 0 solves, pwn. [files.zip](https://score-quals.seccon.jp/files/2481ba1d139e02fed8518fb278ab98ae/files.zip_0b0c98eb5f5f7d7127eb3727ae97efb1a9740b70)*

I didn't have enough time to solve this during the CTF, but it looked interesting so decided to try it afterwards when I had a bit more time on my hands.

We are given a zip with a set of files, one of which is a MIPS binary and the others for lauching a qemu system.

```bash
$ ls files
initramfs.cpio.gz
main
wrapper.py
xinetd.conf
zImage
``` 

A bit strange as it's launching an arm system and the httpd server runing is a 32 bit arm so not sure why we were given a MIPS binary, I ended up just ignoring it.

```bash
$ file httpd
httpd: ELF 32-bit LSB executable, ARM, version 1 (ARM), dynamically linked, interpreter /lib/ld-uClibc.so.0, not stripped
```

The wrapper finds a free port, starts up qemu and forwards that port to the guest httpd server. After a bit of investigation, it looks like a very simple server with three routes, `/`, `/version` and `/echo`. We can make requests to the server, and we also get the debug messages from qemu which is great as they contain the heap address used for the request.


```bash
echo -e "GET /version HTTP/1.0\n\n\n"| nc internet-of-seat.pwn.seccon.jp 41793
HTTP/1.1 200 OK
Content-Length: 5
X-Powered-By: ios-daemon 0.0.1

0.0.1
---- qemu ---
login[237]: root login on 'tty1'
Listening on 8888...
recv: 00004 (0x4015743c) -> 0x00000064 B
```

After a fair bit of RE to try and work out how everything works and a bit of random testing, I came across an issue in `process_chunked` when dealing with the chunk data:
```c
realloc(request->chunkData, chunkSize);
...
if ( bodySize >= request->chunkSize )
      bodySize = request->chunkSize;
memcpy((request->chunkData + request->chunkStart), (bodyStart + request->body), bodySize);
```

So if we add a few extra headers to increase `chunkStart` we can overwrite anywhere past the current chunk.

The binary uses `uClibc` and so the heap is a bit simpler than what we are used to to. The initial heap storage is actually [allocated inline](https://github.com/kraj/uClibc/blob/master/libc/stdlib/malloc/malloc.c#L27) which is great for us as we can overwrite `__malloc_heap`! It's a simple structure that is stored at the end of the arena and looks like this:

```c
struct heap_free_area
{
	size_t size;
	struct heap_free_area *next, *prev;
};
```

So we can overwrite `size` with a large number to make the next alloc return any lower address, like the GOT. All the pages ar rwx was well, so I decided to overwrite `memchr` with the address of our buffer and put the shellcode there. The only other slight hurdle was making sure the shellcode worked with ARMv6.


`SECCON{5ea4f1ee2820cf8d6151937236f8f69e}`


[Full exploit](https://gist.github.com/wbowling/0bde98d198c7e6b45629d70af1f44b3c#file-internet_of_seat-py)