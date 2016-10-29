title: Linux下Glibc 堆的malloc及free过程分析

---

想要搞明白Linux下的堆管理方便学习下Linux下的堆的攻击利用方式，但看了[这篇分析][1]之后感觉在过程上还是不够清晰，于是自己找来Glibc 2.23.90的源码分析了一遍，做了流程上的整理放在这里。链接中已经详细剖析过的结构体等等就不再赘述，主要整理下分配及释放的过程。

<!--more-->

## 分配 ##
（fastbin的分配发生在链表的头部，其余都发生在链表尾部）
（在fast链表中是精确分配（只有大小完全符合才会分配）
    unsorted链表除非是remainder chunk时非精确分配，其余都是精确分配
    small链表在第一遍时是精确分配，第二遍时非精确
    large链表一直都是非精确分配）（注意链表和chunk不一样）
（为毛top chunk必须置位prev_inuse位？翻找了一下说是规定。。。）

1、首先获取Arena的锁，保证安全
2、进行chunk的size检查等（包括将请求size转换为chunk的size，将传入malloc的size加上8 bytes的overhead并向16 bytes对齐（32位下是8 bytes），32位下最小为16bytes，64位下最小为32bytes）
——一种情况是没有可用Arena
没有可用Arena会直接交由sysmalloc处理，进入后直接尝试mmap分配，失败返回0
——另一种情况是有可用Arena
1、如果请求属于Fast bin大小，就从Fast bin中分配，失败则进行normal bin的分配过程（分配成功后有fastbin的index的反向计算的安全检查再返回）（中间运用了原子操作来优化从链表中删除chunk）
2、然后再判断是否属于small bin，是的话找到对应bin链表的最后一个chunk进行分配（期间也有安全性检查，到small bin时才会有arena的初始化检查），否则计算再large bin中的index再清fastbin，进入下一步（在这一步时确定了index）
3、开始遍历unsorted bin，如果属于small bin且Last Remainder chunk是unsorted bin 中的唯一一个chunk并且能够满足大小，那么切割这一chunk进行分配，并把剩余部分继续成为remainder chunk放入unsorted bin，如果大小能够精确匹配目标（不管是small还是large），就分配这一chunk返回，否则放入相应的small 链表或large 链表（维持large 链表从大到小的顺序），遍历unsorted bin不会超过MAX_ITERS，超过的话即使unsorted 链表中还有可能可以分配的chunk也直接到下一步
4、如果是large bin，根据算出的index找到对应链表，如果链表为空或者链表中的最大chunk也不能满足，进入下一步，否则就开始倒序查找（使用nextsize指针，该指针指向下一个不同大小的正序中的第一个的chunk），找到后分割返回（如果分割后剩余大小不够MINSIZE就不分割），把分割后的chunk放入unsorted bin头部（如果该chunk为large 设置该chunk的两个nextsize指针为NULL）
5、使用binmap从之前确立的bins中的index链表开始，使用binmap加快搜索，找到最适合的可分配的链表（使用位运算，如果没有直接跳到下一步），然后拿出链表最后一个chunk（大小肯定是够的），然后分割分配（如果分割之后的大小小于MINSIZE就不尽兴分割），然后剩下的成为remainder chunk放入unsorted bin头部（和之前一样），然后返回
6、开始使用top chunk分配，先看top能不能满足，如果能满足切割分配，剩下的继续成为top chunk，否则看是否还有fastbin，如果有进行清fastbin操作再重新计算index，跳转到3继续循环（源码注释中说这样的循环最多这么一次，因为本来唯一可能循环的路径（存在fastbin）下一次不可能再满足），否则进行sysmalloc然后返回

#### 关于sysmalloc ####
1、只要要分配的chunk大小超过阈值且已经mmap的内存数量没超过阈值，就会进行mmap分配（或者没有获取到arena也会mmap，mmap分配失败就会直接返回0）
2、然后看是否是main_arena，不是的话试图grow当前heap，失败则mmap一个新的heap，开辟新的heap后将old top chunk末端设置两个fencepost（就是一个极小的被标记为以使用的chunk，应该比MINSIZE还小，应该是8字节，在当前heap的最末端，如果top chunk大小不够MINSIZE，就全部设置为fencepost），然后free掉被删掉fencepost的top chunk（应该是放入到unsorted中），如果尝试new_heap也失败了还没有试过mmap分配，去尝试mmap分配
如果是main_arena，调整所需的size进行brk分配，失败则尝试mmap分配，然后根据结果进行调整（处理一下分配失败、brk不增反减的情况，处理contiguous标志等等）
最后再从top chunk中分配

#### 按fast bin、small bin、large bin分 ####
1、fast bin就是看一下fast链表，有正好合适的就分，否则和small 一样
2、small bin先看small bins中有没有，然后遍历unsorted bin寻找（通过精确或者remainder，unsorted chunk 会被放回相应的small bin或large bin），然后使用binmap进行尽量合适分配（任何一次分割剩下的会成为remainder chunk，除了top），再不然就top或找系统
3、large bin直接找unsorted bin，不行就往后找（使用binmap），否则top或系统

#### 关于巨块的分配 ####
没有看到源代码中有对于巨块的直接交给mmap处理的代码，应该是跟着整个流程走一遍然后能分配就分配否则mmap
mmap分配的未必就一定是大的chunk

## 释放 ##
（所有chunk的释放都是插入链表头部）
然后做一些基本的检查，比如size大小等
1、如果是fast bin直接返回给fast bin，在fast bin中不会发生合并（chunk一直被标记为占用）
2、然后如果不是mmap的内存（属于normal bin），看看前后能不能合并，能合并就合并后加入到unsorted bin链表头
合并之后看合并之后的chunk的size，如果大于FASTBIN_CONSOLIDATION_THRESHOLD，会清fastbin，能合并的合并，然后全部放到unsorted bin链表中，然后试图收缩heap
（其中如果回收的块是和top chunk相邻的，就直接合并到top chunk中去（如果TRIM_FASTBINS为1（我看到的源码里默认为0），fastbin也会进行合并，否则不合并），并且这些操作中间或有获取锁的操作保证安全）
3、直接munmap返回给操作系统

#### 来自源码中的注释 ####
chunk不会被放回到normal bin中直到它们获得一次被malloc的机会
Chunks are not placed into regular bins until after they have been given one chance to be used in malloc

#### 关于获取Size ####
获取fd的size是将当前指针＋当前size后－4，获取bk的size是直接用当前chunk中的prev_size（如果前一个chunk正在使用的话似乎也不用获取他的size）

## 关于堆的收缩 ##
如果top chunk的大小过大（应该是超过一个heap segment，但是参考中的中文资料说子线程中的Top chunk一旦达到一个Heap Segment大小就会在这次free操作时归还给操作系统，但是如果整好处于边缘值岂不会造成mmap－munmap－mmap－munmap的浪费操作？）会将这块内存还给系统，但是会至少留下一部分内存继续作为top chunk

#### 来自源码中的注释 ####
收缩过程使用madvise的MADV_DONTNEED标志，表明这块内存不会再被访问，这是向内存管理器发出的建议，内存管理器会采取适当处理



最后附一张图：
![heap.png][2]


[1]: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
[2]: /images/linux_heap_analysis0.png
