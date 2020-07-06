##  ► rev
### Initial checks

1. file
2. wxHexEditor (patching,diffing)
2. strings
3. readelf
4. md5sum
5. objdump –d
6. ltrace ./file (library calls)
7. strace ./file (system calls)

### Tools

GDB

- Break at an offset from function `(gdb) b *main+128`
- **How to print strings when you have their name (symbol)?**
- Examine general format: `x/nfu addr`
- To examine a double word (giant): `x/xg addr`
- Changing variable values `set var <variable_name>=<value>`
- Disable SIGALRM `handle SIGALRM ignore`
- Remove all breakpoints using `d`
- Address of a variable `p &var`
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

- Learn about `send` and `recv`

### Resources

Awesome

- https://medium.com/@vignesh4303/reverse-engineering-resources-beginners-to-intermediate-guide-links-f64c207505ed

Books

- Reverse Engineering for Beginners
- Practical Reverse Engineering
- Practical Malware Analysis
- Linux Device Drivers
- Windows Internals
- Debugging with GDB
- The IDA Pro Book
- Radare2 Book
- Ghidra Book

Courses

- RE101 - Malware Unicorn
- ARM reversing - Azeria

### Assembly

Basics

- Byte (8 bits), word (16 bits) and double word (32 bits)
- RAX: 64-bit, EAX: 32-bit value, AX is the lower 16-bits, AL is the lower 8 bits, AH is the bits 8 through 15 (zero-based).
- Passing arguments:
    - 64-bit: first four arguments rdi, rsi, rdx, rcx rest on the stack.
    - 32-bit: push arguments on to the stack (include them in the payload).
    - Arguments are pushed before the EIP in reverse order (right-to-left).
- .bss segment is used for statically-allocated variables that are not explicitly initialized to any value.

Instructions

- LEAVE: equivalent to `mov esp,ebp; pop ebp`
- CALL: push address of next instruction and change eip to given address.
- MOVS/MOVSB/MOVSW/MOVSD: move data from string to string.
- MOVSX: move with signed extension.

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

### Todo

- Windows binaries (x64dbg)
- Kernel exploitation
- Browser explotation
- Z3 & angr framework
- Fuzzing (AFL/ASAN)

