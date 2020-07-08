##  ► pwn
### Todo

- Windows binaries
- ARM exploitation
- Kernel exploitation
- Browser explotation
- Z3 & angr framework
- Fuzzing (AFL/ASAN)

### Initial checks

1. file
2. strings
3. readelf
4. md5sum
5. objdump –d
6. checksec
7. wxHexEditor (patching,diffing)
8. ltrace ./file (library calls)
9. strace ./file (system calls)

### Resources

Courses

- https://ropemporium.com/
- https://sidsbits.com/Path/
- https://overthewire.org/wargames/narnia
- ARM reversing - Azeria
- RE101 - Malware Unicorn
- [Ultimate guide to reversing](https://medium.com/@vignesh4303/reverse-engineering-resources-beginners-to-intermediate-guide-links-f64c207505ed)

Books

- Reverse Engineering for Beginners
- Practical Reverse Engineering
- Practical Malware Analysis
- Linux Device Drivers
- Windows Internals

Tools

- Debugging with GDB
- The IDA Pro Book
- Radare2 Book
- Ghidra Book

### Notes

-  newline is required at the end of your payload to cause the binary to process your input.
- `fgets` means you can use null bytes in your payload but not newlines.
- `gets` ends at newline or EOF, while `strlen` stops at null byte.
- `nm <binary> | grep ' t '`
- `pwndbg> info functions`
- `dmesg | tail`
- `pwn cyclic`

### Assembly

Basics

- Byte (8 bits), word (16 bits) and double word (32 bits)
- RAX: 64-bit, EAX: 32-bit value, AX is the lower 16-bits, AL is the lower 8 bits, AH is the bits 8 through 15 (zero-based).
- Passing arguments: https://ctf101.org/binary-exploitation/what-are-calling-conventions/
    - 64-bit: first four arguments rdi, rsi, rdx, rcx rest on the stack.
    - 32-bit: push arguments on to the stack (include them in the payload).
    - Arguments are pushed before the EIP in reverse order (right-to-left).
- `.bss` segment is used for statically-allocated variables that are not explicitly initialized to any value.
- Least significant three nibbles are the offset within a page (4KB) `3*4=12 => 2^12 = 4*(2^10)`

Instructions

- LEAVE: equivalent to `mov esp,ebp; pop ebp`
- CALL: push address of next instruction and change eip to given address.
- MOVS/MOVSB/MOVSW/MOVSD: move data from string to string.
- MOVSX: move with signed extension.
- BND: the return target should be checked against the bounds specified in the BND0 to BND3 registers

Coding in assembly

- 64-bit: `$ nasm -felf64 hello.asm && ld hello.o && ./a.out`
- 32-bit: `$ nasm -felf32 -g -F dwarf eip.asm && ld -m elf_i386 -o eip eip.o`
- In gdb, you can set breakpoint for the asm program using its labels, for example `b _start`
- [Running assembly in C](https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/asm3.md)
- We usually use `_start` in assembly similar to how we use `main` in C.
- Therefore we often break at `_start` within gdb.
- Use `fin` to continue until current function finishes.

### C

32-bit compilation

```
$ sudo apt install gcc-multilib
$ gcc -m32 test.c -o test
```

Signedness

- Make sure to use `%u` format specifier for unsigned data-types.
- The CPU does not care about signed and unsigned representations.
- We can see the difference while shifting integers and overflows.
- The conditional opcodes help differentiate in signedness.

Datatypes

- For `uint_` related datatypes you need to `#include <stdint.h>`

### GOT and PLT

- The first time you make a call to a function like `printf` that resides in a dynamic library, it calls `printf@plt`
- Within `printf@plt` it jumps into `printf@got.plt` that is we jump to whatever address is stored in the GOT.
- From there we go to `_dl_runtime_resolve` which is in the dynamic linker `ld.so` which helps set up external references to libc.
- Next time onwards we directly jump to `printf` from the GOT.

Resources

- https://ropemporium.com/guide.html (appendix A)
- https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- https://refspecs.linuxbase.org/LSB\_3.1.1/LSB-Core-generic/LSB-Core-generic/specialsections.html

### Format String Attacks
**Offset notation: `%6$x`**

- *read-where* primitive: `%s` (for example, `AAAA%7$s` would return the value at the address 0x41414141).
- *write-what-where* primitive: `%n`
- `%hhn` lets us write one byte at a time.

Reading from an arbritrary address

1. Get address of string to be read. `rabin2 -z <binary>`
2. Find the offset from the stack where the input is stored: `%x.`then `%x.%x.` then `%x.%x.%x.` and so on until you see the ascii values`25782e`
3. Once you know the offset, store the address to be read at that offset by typing it in as the first thing in the buffer and then use the offset you found out to go read in that address: `python -c 'print "\xef\xbe\xad\xde%6$s"' | ./<binary>`

Writing to an arbritrary address

```
TBD
```

Overwriting the GOT

```
TBD
```

### Leaking libc, functions, canaries

Using format string attacks

- http://abhaynayar.com/blog/asis.html
- https://srikavin.me/blog/posts/5d87dbe86e58ed23d8620868-nactf-2019-loopy-0-1#Loopy--0-1 

Leaking libc base

- See pico2018/got-2-learn-libc
- http://abhaynayar.com/blog/asis.html
- First somehow get the address of puts during runtime.
- One way to do that is to use puts itself to print its address by using a buffer overflow (+ROP chain).
- Then subtract it from the puts offset from the given libc binary.
- **Remember to use given library / your library depending on where you're testing.**
- libc.address = puts\_runtime - libc.symbols['puts']

Leaking functions

- This is similar to leaking libc base, but with a function.
- https://sidsbits.com/Defeating-ASLR-with-a-Leak/
- https://www.youtube.com/watch?v=evug4AhrO7o
- Get the address of `puts` using `(gdb) x puts`
- Get the address of `system` using `(gdb) system`
- Get the offset between them.
- Get the address of `puts` while running the program.
- Now, you can call `system` using address of `puts` minus the offset you calculated earlier.

### Return oriented programming

Getting a shell

- Use a call to `system` by passing shell command as the only argument
- **Make sure to `call system` not simply jump to it** (for eg: mov eax,_system_ then call eax)
- If you want to directly jump to it, make sure to append a dummy return address and a parameter after it: `payload="A"*offset + system + "AAAA" + binsh`
- Use `syscall(x)`to call to`execve('/bin/sh', NULL,NULL)`
- find "x" from: `https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64`

Writing to memory (in case you want "/bin/sh")

1. Look for gadgets like `mov [reg], reg ` (alternatively use something like`fgets`)
2. Look for places to write to using `readelf -S <binary> ` or ` rabin2 -S <binary>` (don't forget to consider the size)
3. Write the string to the address using the gadget found in step 1.
4. Call `system` with address of the written string.

### Heap exploitation

Bins

- There is also an array of pointers called bins.
- They point to doubly linked lists of chunks.
- These are chunks that were allocated and then freed.

Chunks

- Chunks are aligned by 8 bytes in memory.
- Fields in a chunk:
    1. prev\_size: used only if previous chunk is free, otherwise both chunks use the same size variable as if merged.
    2. size: contains the size of the current chunk.
    3. \*fd: pointer to the next chunk.
    4. \*bk: pointer to the previous chunk.

Top chunk

- At the beginning, there’s only one big chunk (top) in the arena (called wilderness).
- Every time `malloc` is called it first checks if a same size chunk can be found in the bins.
- If not, it will take a bite out of the top chunk and return the pointer.

Flags

- There is no flag to tell whether the current chunk is allocated or not.
- Therefore they are eight bytes aligned and the last three bits of the size field are used as flags.
- The flags are (LSB to MSB): PREV\_INUSE (if previous chunk is allocated), IS\_MMAPPED (if mmap used), NON\_MAIN\_ARENA (if not stored in main arena).
- To know whether a chunk is free or not, we need to add size to the pointer of the current chunk and see the PREV\_INUSE flag of the next chunk.

Using gdb wrappers for heap

- Use `vmmap` to see heap region.
- Heap will only come up once `malloc` has been used.
- Use `heap chunks` in gef or `vis_heap_chunks` in pwndbg to see the chunks in heap.

```
+-----------------+
|   application   |
+-----------------+
|   heap          |
+-----------------+
|   libraries     |
+-----------------+
|   stack         |
+-----------------+
```

Gynvael's stream

- User mode programs can ask for one page of memory from the kernel mode.
- This is why we need heap, since we don't want to waste an entire page everytime we need something.
- mmap is used to get virtual memory pages from the os (on windows it's called virtual alloc).
- printf requests a page using mmap because standard output is buffered.
- Towards the end of an elf file is a section used as heap and `brk` is used to extend it.
- When malloc-ing a lot of stuff, if the pages of allocation change it means a new heap is created (?).

### Tools

GDB

- `step` steps into subroutines, but `next` will step over subroutines.
- `step` and `stepi` (and the `next` and `nexti`) are distinguishing by "line" or "instruction" increments.
- In most of my use-cases I need `nexti` (short `ni`)
- To find address of a variable: `(gdb) p &var`
- While printing variables if it is an unknown type use `(gdb) p (int)var`
- Break at an offset from function `(gdb) b*main+128`
- To get out of current function use `(gdb) finish`
- To list all functions `(gdb) info functions regex`
- To learn the relationship between higher level code and assembly better, use the -ggdb option while compilint. 
- When GDB opens via debug(), it will initially be stopped on the very first instruction of the dynamic linker (ld.so) for dynamically-linked binaries.
- To view the source (and provide more debugging info) use -ggdb flag while compiling with `gcc`
- How to set ASLR on on gdb (turns off every instance): `set disable-randomization off`
- How to print strings when you have their name (symbol)?: `p str` then `x/s`
- Examine general format: `x/nfu addr`
- To examine a double word (giant): `x/xg addr`
- Changing variable values `set var <variable_name>=<value>`
- Disable SIGALRM `handle SIGALRM ignore`
- Remove all breakpoints using `d`
- Disassemble function from the command line: `$ gdb -batch -ex 'file /bin/ls' -ex 'disassemble main'` or `gdb -q ./a.out 'disass main'`
- Ghidra decompilation in pwndbg: `ctx-ghidra sym.foo()`
- Execute python in gdb: `(gdb) python print('asdf')`

IDA

- Open strings window using `Shift + F12`. Can also open during debug mode.
- Change between basic and graphic mode (space bar)
- Rename variables: (n)
- Comment –Side: (:), (;) –Above/below: (ins)
- Convert const formats: (right-click)
- Cross-reference: (x)
- Change to array: (a)
- IDA-Options-General-auto comment
- IDA-Options-General-opcode bytes 8 

_Source: RPISEC-MBE_

pwntools

- Learn about `fit`
- Learn about `send` and `recv`
- Use `recv()` to receive everything up till that point.
- Sometimes remote connection might be close due to an error in your python code (such as bytes != strings).
- For passing args: `io = process(['./chall','AAAA'])` or `io = gdb.debug(['./chall','AAAA'], 'b main')`
- When nothing works try `io.interactive()`
- Creating a template `pwn template ./<binary> --host 127.0.0.1 --port 1337`
- Debugging with gdb `io = gdb.debug('./<binary>', 'b main')`
- Passing commandline arguments `io = process(['./crackme','blah'])`
- Shell code `shellcode = asm(shellcraft.sh())`
- Cyclic padding
	- In the terminal `pwn cyclic 200` and  `pwn cyclic -l 0xdeadbeef`
    - In python:

```python
x = 4 #x=8 for 64-bit
io.sendline(cyclic(200, n=x))
io.wait()
core = io.corefile
offset = cyclic_find(core.read(core.esp, x), n=x) #rsp for 64 bit
offset -= x # wherever the sequence is found, we replace it
```

- Return oriented programming: ropper, ROPgadget, angrop, one\_gadget

```python
# leaking libc
elf = ELF('./vuln', checksec=False)
rop = ROP(elf)

#rop.raw(0)
#rop.raw(unpack(b'abcd'))
#rop.raw(2)

#rop.call('read',[4,5,6])
#rop.exit()

#rop.write(7,8,9)
#print(rop.dump())

#rop.call('execve', ['/bin/sh', [['/bin/sh'], ['-p'], ['-c'], ['ls']], 0])
#print(rop.chain())

pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main_plt = elf.symbols['main']

rop = offset + p64(pie+pop_rdi) + p64(pie+puts_got) + p64(pie+puts_plt) + p64(pie+main_plt)
```

