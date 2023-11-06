from zio import *

io = zio(('119.3.81.43', 1338))
lines = open("./x.js", "rb").readlines()
for l in lines:
    io.writeline(l)
io.writeline("EOF")
io.interact()