from pwn import *

elf = ELF('./hof', checksec=False)
print('target at:', hex(elf.sym.target))

io = gdb.debug('./hof', 'b main')
#io = process('./hof')

io.sendline('fdsa')
print(io.recvall())


