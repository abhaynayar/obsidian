##  ► pwn

★ Some resources:
- https://sidsbits.com/Path/
- https://ropemporium.com/
- https://overthewire.org/wargames/bandit/

### Initial checks
- ```file <binary>```
- ```strings <binary>```
- ```checksec <binary>```
- ```./<binary>```

### Things to keep in mind
- byte (8 bits), word (16 bits) and double word (32 bits)
- RAX: 64-bit, EAX: 32-bit value, AX is the lower 16-bits, AL is the lower 8 bits, AH is the bits 8 through 15 (zero-based)
- fgets() means you can use null bytes in your payload but not newlines
- newline is required at the end of your payload to cause the binary to process your input
- what does ```call``` do?
  1. pushes address of next instruction on to the stack
  2. changes ```eip``` to given address
- passing arguments
  - _64 bit_ : first four arguments rdi, rsi, rdx, rcx
  - _32 bit_ : push arguments on to the stack (include them in the payload)

### Finding function addresses
- ```nm <binary> | grep ' t '```
- ```pwndbg> info functions```

### gdb
- <https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf>
- Address of a variable ```p &var```
- Changing variable values ```set var <variable_name>=<value>```
- Disable SIGALRM ``` handle SIGALRM ignore ```

### pwntools
- Creating a template ``` pwn template ./<binary> --host 127.0.0.1 --port 1337 ```
- Debugging with gdb ``` io = gdb.debug('./<binary>', 'b main') ```
- Passing commandline arguments ```io = process(['./crackme','blah'])```
- Shell code ``` shellcode = asm(shellcraft.sh()) ```
- Cyclic padding ``` pwn cyclic 200```   ``` pwn cyclic -l 0xdeadbeef ```
### Return Oriented Programming

#### Finding gadgets
- ``` ropper -f <binary>```
- ``` ROPgadget --binary file_name > gadgets.txt ```

#### Rejecting bad characters
- ``` ropper -b <badbytes> ```
- ``` ROPgadget --badbytes <byte> ```

#### Automatic ROP generation
- ``` ropper --chain "execve cmd=/bin/sh" -f <binary> ```
- ``` ROPgadget --ropchain --binary <binary> ```
- https://github.com/salls/angrop

#### Getting a shell

- use a call to system() by passing shell command as the only argument (★ make sure to ```call system``` not simply jump to it, i.e., the call to system should already be there in the binary)
- use ```syscall(x)``` to call to ```execve('/bin/sh', NULL,NULL)```
- find "x" from: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

#### Writing to memory

1. look for gadgets like ``` mov [reg], reg ``` (alternatively use something like ```fgets```)
2. look for places to write to using ``` readelf -S <binary> ``` or ``` rabin2 -S <binary> ```
   (don't forget to consider the size)
3. write the string to the address using the gadget found in step 1.
4. call system() with address of the written string.

★ in case you have leaked it, libc might already have the string

#### Leaking libc.so.6

- understand dynamic linking
  - https://ropemporium.com/guide.html (appendix A)
  - https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- using a format string vulnerability (https://srikavin.me/blog/posts/5d87dbe86e58ed23d8620868-nactf-2019-loopy-0-1#Loopy--0-1)
- leaking the address of puts (https://sidsbits.com/Defeating-ASLR-with-a-Leak/)

#### Leaking stack canaries
#### Heap overflow

### Format String Attacks
#### Reading from an arbritrary address
1. Get address of string to be read. ``` rabin2 -z <binary> ```
2. Find the offset from the stack where the input is stored to do this %x. then %x.%x. then %x.%x.%x. and so on until you see the ascii values 25782e.
3. once you know the offset, store the address to be read at that
   offset by typing it in as the first thing in the buffer and then
   use the offset you found out to go read in that address.
```
python -c 'print "\xef\xbe\xad\xde%6$s"' | ./<binary>
```

- Offset notation ``` %6$x ```
