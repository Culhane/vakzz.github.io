---
layout: post
title: vectors - Blaze CTF 2018
date: '2018-04-27 23:00:00'
---

> rust guarantees security right?
> 
> blizz here: vectors.420blaze.in tcp port 420
> 
> Author : aweinstock
> [vectors](https://github.com/vakzz/ctfs/raw/master/Blaze2018/vectors/vectors) [libc](https://github.com/vakzz/ctfs/raw/master/Blaze2018/vectors/libc_02ad2eb11b76c81da7fc43ffe958c14f.so.6)

*420 points, 5 Solves, pwn*

We are given a rust program that has a list of 10 vectors, showing the memory location, size, and capacity and some actions that we can perform.

```haskell
$ ./vectors
0x7fec7d564010, 0, 32
0x7fec7d564120, 0, 32
0x7fec7d564230, 0, 32
0x7fec7d564340, 0, 32
0x7fec7d564450, 0, 32
0x7fec7d564560, 0, 32
0x7fec7d564670, 0, 32
0x7fec7d564780, 0, 32
0x7fec7d564890, 0, 32
0x7fec7d5649a0, 0, 32
read/write/push/pop>
```

After a bit of messing around I noticed that there is a strange mapping to a tmp file:

```python
0x00007f8f3adef000 0x00007f8f3ae15000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.23.so
0x00007f8f3afe9000 0x00007f8f3afee000 0x0000000000000000 rw-
0x00007f8f3b011000 0x00007f8f3b012000 0x0000000000000000 rw- /tmp/map2019737541
0x00007f8f3b012000 0x00007f8f3b014000 0x0000000000000000 rw-
0x00007f8f3b014000 0x00007f8f3b015000 0x0000000000025000 r-- /lib/x86_64-linux-gnu/ld-2.23.so
```

Examining it shows that it is where all our vectors are stored, initailly the first 32 values are stored inline, but if you go above that then a new block is allocated and the address is stored instead.

Up to 32 values:
```python
telescope 0x00007f476a674000
0x00007f476a674000│+0x00: 0x0000000000000020   # size field
0x00007f476a674008│+0x08: 0x0000000000000000   # inline or allocated flag
0x00007f476a674010│+0x10: 0x0000000000001234
0x00007f476a674018│+0x18: 0x0000000000001234
```

Adding the 33rd value:
```python
0x00007f476a674000│+0x00: 0x0000000000000021 ("!"?)
0x00007f476a674008│+0x08: 0x0000000000000001
0x00007f476a674010│+0x10: 0x00007f476943f000  →  0x0000000000001234
0x00007f476a674018│+0x18: 0x0000000000000040 ("@"?)
```

The name of the file is generated with a random number but seeded with `srand(time(0))`. This means that if we start two processes as the same time, both will be using the same file to back the mapping.

There was bound checking done when reading and writing a value, but it was done before you entered the final value. So with two processes, we push 32 values to the array with p1, then start to write to index 0 with p2 but before the final step we push another value with p1. The inline vector gets converted to an allocated one, and now when we finish the write with p2 in index 0 we are now overwriting the address of the new vector.

Setting this the the base address of the mapped file allows us to modify the length to `0xffffffffffffffff`  and the vector address to `0x0` allowing us to read and write to any address. Then it was just a matter of leaking all the required values and finding something to overwrite. `ld.so` was mapped at a fixed offset from the temporary file, and from that I found `memalign` to give the libc base and then `environ` to get the PIE base.

This final step was harder than I expected, as none of the usual hooks would work for a rust binary. Finally I found `std::panicking::HOOK::h40bfd8fd5660cc20` which is called by `std::panicking::rust_panic_with_hook::h8dcdd9a7e80a2917()` which has the great advantage of also being able to set the first argument! Replacing this with the address of `"/bin/sh"` and `system` and causing a panic triggers a shell.

[Full solution here](https://github.com/vakzz/ctfs/blob/master/Blaze2018/vectors/pwn.py)
