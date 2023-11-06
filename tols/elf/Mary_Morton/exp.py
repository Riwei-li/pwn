from pwn import *
#p = process("./pwn")
p = remote("61.147.171.105",51848)

p.sendline(payload)
p.interactive()

