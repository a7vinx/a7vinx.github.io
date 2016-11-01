title: CSAW 2016 Rock writeup

date: 2016/09/19 15:48:00

---

100分的Reverse

由于是C＋＋的程序，所以一开始看起来很杂乱，经过分析之后程序的主要逻辑是这样：

<!--more-->

![csaw_2016_rock_writeup0.png][1]

一开始用到一个结构体，大概长这样：

![csaw_2016_rock_writeup1.png][2]

分析之后的逻辑就比较简单了，主要就是对输入的字符串进行逐个异或以及加法运算。写个脚本反过来算一遍就好了，但是一开始没注意到图中加注释的两行函数的操作不是加在原始字符串上的，而是新开了内存在操作后面直接丢弃了，所以第一次写的脚本跑出来根本不对... 然而一时又没找到哪里有问题，这时看它最后的输出可以用于直接爆破，就干脆写个爆破脚本，所以最后还是爆破出来的...

正常版本脚本：

```python
fstr='FLAG23456912365453475897834567'

def add_xor_str(s,added,xored):
	ret=''
	for x in s:
		x=ord(x)+added
		x=x^xored
		ret+=chr(x)
	return ret

def decrypt(fstr):
	fstr=add_xor_str(fstr,-9,0x10)
	fstr=add_xor_str(fstr,-20,0x50)
	# these two lines are useless because operations about these two lines
	# in origin program does not has effect on origin input string
	# fstr=add_xor_str(fstr,-35,0x20)
	# fstr=add_xor_str(fstr,0,0x50)
	print fstr

decrypt(fstr)
```

爆破版本：

```python
from pwn import *

def testn(ps,n):
	for x in range(33,127):
		nows=ps[:n]+chr(x)+ps[n+1:]
		p=process('rock')
		p.sendline(nows)
		recv=p.recvall()
		# get number
		final=recv[-2] if n<10 else recv[-3:-1]
		p.close()
		print 'recv: '+recv[-10:]
		try:
			if int(final)==n:
				continue
			else:
				return nows
		except Exception as e:
			return nows
		

s='ABCDEFGHIJKLMNOPQRSTUVWXYZABCD'
for i in range(0,30):
	print '------------------------------------'+str(i)+'-------------------------------------'
	s=testn(s,i)
print s
```





[1]: /images/csaw_2016_rock_writeup0.png
[2]: /images/csaw_2016_rock_writeup1.png

