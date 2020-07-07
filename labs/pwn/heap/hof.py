from pwn import *

r = gdb.debug('./hof','b main')
r.interactive()

