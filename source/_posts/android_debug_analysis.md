title: Android 动态调试原理浅析

date: 2016/10/25 12:06:00

---

又是一番坎坷的折腾，Android之路刚开始就这么折腾，但好在最后终于能够解决并能给自己一个满意的答案。也是有一次见识到了国内的资料都是转转转的可怕，只是这次也并没有找到相关的英文资料可以解惑，记录在这里算是一点补充，让需要的朋友少走点弯路。

<!--more-->

## 姿势总结

首先简单总结下，目前在Android的动态调试主要有这么几种姿势：
- **smali插桩**
  较为麻烦的方式,在smali代码中插入自己的代码来做log输出等达到调试的效果
- **IDA调试**
  IDA可以支持调试dex和so，但是并不能自由切换，经过尝试，可以通过开两个IDA分别调试dex和so来达到这个效果
- **JEB调试**
  2.2.x以上已经支持dex和so的完美调试，但是貌似不能调试so库中的JNI_Onload以及.init中的函数？
- **gdb调试**
  gdb+gdbserver 可以用来调试so库
- **android studio调试**
  可以调试smali，可以调试ndk但是貌似不能在无源码的情况下调试so，都是通过插件的方式实现的貌似，具体没做尝试
- **andbug开源项目**
  貌似不是很好用，忽略
- **xposed hook**
  只能进行函数开始和结束地址处的hook？这个也需要尝试一下

## 原理简介

Android上App的调试主要有两个部分，dex的调试或者说VM的调试以及so库代码的调试。而这两个暂时看来是需要两个调试器来完成（或者有哪个调试器同时实现了进程的调试以及JDWP协议来调试VM应该就可以包揽这俩），对于so库代码的调试主要是通过类似gdb ptrace调试的方式来实现，对于VM的调试主要是通过jdwp协议来实现，这个协议是类java虚拟机提供的一个调试接口，Dalvik虚拟机显然也实现了这个接口。而这个JDWP协议应该是通过UNIX域套接字来完成VM与debugger之间的通信的。


有关JDWP协议adb有些操作需要了解下：
```
adb jdwp
```
列出目标Android系统中支持jdwp协议的进程
```
adb forward tcp:XXX jdwp:XXX
```
将本机的端口映射到（通过USB或者端口，取决于本机与目标Android之间建立连接的方式）目标Android的一个jdwp接口上。

## 关于IDA

然后下面主要就是对于IDA的两种调试方式的分析，算是对蒸米大大的《安卓动态调试七种武器之孔雀翎 – Ida Pro》一文的一些补充，能够搜到的相关IDA调试的资料基本都是一样的，就是和蒸米大大这篇一样把步骤列一遍，但是我看的时候却憋得慌，主要的问题就是不明白为什么要在中间插一步jdb，于是相当憋得慌。经过一番考证，终于找到了原因。

我们先看下IDA调试dex的过程，步骤这里就不列了，一搜一大把，主要看下原理，使用USB连接，当IDA已经连接到VM之后，可以看到：

![android_debug_analysis0.png][1]

![android_debug_analysis1.png][2]

IDA是通过adb建立了一个jdwp转发来调试目标VM，图中的另外一个与adb建立的连接是我开的shell，这个时候也是没有别的连接的，IDA在这个时候并没有通过android_server来进行调试。

然后我们来重点看下调试so库，在蒸米大大列出的步骤里，说必须要启动ddms，然后还要jdb插一脚，这我果断不能忍，IDA这么6，为什么还需要再额外找东西插一脚？原因是这样的，打开ddms之后，可以看到：

![android_debug_analysis2.png][3]

![android_debug_analysis3.png][4]

ddms建立了一堆连接与监听，所以之后的那个jdb connect是连接到了java然后通过java处理再通过adb来与目标VM建立调试通信，所以如果没有开ddms，localhost没有这些监听端口你connect到127.0.0.1:8700自然没有办法attach到目标VM上，这算是解决了问题1。下面是问题2，为什么需要jdb插一脚，在IDA开始调试so库后我们可以看到它这次是直接与android_server进行通信：

![android_debug_analysis4.png][5]

没有与jdwp进行连接，所以这个时候由于是debug方式启动的app，VM还在等待jdwp发过来的信号而暂停，只能通过jdb来让它继续运行（所以android_server实现的还不够完美？）。那有没有办法不让jdb插一脚呢？我猜想双开IDA，一个调DEX，一个调so应该可以做到，尝试之后证明这样确实没有问题，于是到这里问题2也终于有了答案，我心中的一口淤血也算是终于吐出来了。

也希望能让诸位看官对这个答案感到满意。

## 一些坑


最后是一些坑，我在这里折腾了整整两天，除去jdb这里的疑惑之外，另一个阻拦我的问题也终于能够解决，其实如果我能先把蒸米大大对于Alicrackme_2.apk的分析看完的话根本就不会遇到那个另一个问题，然而我以为对那个apk的分析到IDA调试就完了...谁知道那个apk是有反调试的！坑啊，我一开始怎么也进不去so库中的调试，还以为是IDA在wine下运行的问题，又试了windows下的IDA，jeb也不行，我也试了windows下的，然后又各种排除，一开始有那么一瞬想到是不是apk怎么样，但是就那么一瞬一闪而过，想拿jeb官方演示的apk看看但是没找到就想算了小小的crackme2能有什么问题...我真的是懵逼的啊后来发现这个反调试的trick的时候，这样很多东西都全部都能说通了，比如为什么jeb已经出来两个debugger了却不能调试so，比如IDA为什么只能调试JNI_onload却不能断在后面的check函数里，还是too naive啊...

但还是有些其他的坑：
1、IDA调试so库的时候不能使用adb远程连接，只能使用USB否则IDA老是崩，我不确定是不是因为wine的缘故因为还没验证
2、IDA调试so的时候，在已经attach之后需要重新确认下debug option中的断在lib加载处是否还勾着，我这里即便之前勾上了attach之后就没了需要重新勾一下

最后就是关于jeb的资料还太少，不过貌似jeb不能调试.init和JNI_onload，因为即便我断在lib中也不会停下，不知道是不是还有什么姿势，我翻遍了jeb也没看到什么相关的内容，有知道的朋友吗？不胜感激～




[1]: /images/android_debug_analysis0.png
[2]: /images/android_debug_analysis1.png
[3]: /images/android_debug_analysis2.png
[4]: /images/android_debug_analysis3.png
[5]: /images/android_debug_analysis4.png
