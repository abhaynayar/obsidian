##  ► rev
### Assembly
Basics:

- Byte (8 bits), word (16 bits) and double word (32 bits)
- RAX: 64-bit, EAX: 32-bit value, AX is the lower 16-bits, AL is the lower 8 bits, AH is the bits 8 through 15 (zero-based)
- Passing arguments
    - 64-bit: first four arguments rdi, rsi, rdx, rcx rest on the stack
    - 32-bit: push arguments on to the stack (include them in the payload)
    - Arguments are pushed on to the stack in reverse order

Instructions:

- LEAVE: equivalent to `mov esp,ebp; pop ebp`
- CALL: push address of next instruction and change eip to given address.
- MOVS/MOVSB/MOVSW/MOVSD: move data from string to string.
- MOVSX: move with signed extension.

Coding in assembly:

- 64-bit `$ nasm -felf64 hello.asm && ld hello.o && ./a.out`
- 32-bit: `$ nasm -felf32 -g -F dwarf eip.asm && ld -m elf_i386 -o eip eip.o`
- In gdb, you can set breakpoint for the asm program using its labels, for example `b _start`
- [Running assembly in C](https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/asm3.md)

### C

Signedness:

- Make sure to use `%u` format specifier for unsigned data-types.
- The CPU does not care about signed and unsigned representations.
- We can see the difference while shifting integers and overflows.

Datatypes:

- For `uint_` related datatypes you need to `#include <stdint.h>`

### Tools
#### GDB

- Examine general format: `x/nfu addr`
- To examine a double word (giant): `x/xg addr`
- Changing variable values `set var <variable_name>=<value>`
- Disable SIGALRM `handle SIGALRM ignore`
- Remove all breakpoints using `d`
- Address of a variable `p &var`
- Disassemble function from the command line: `$ gdb -batch -ex 'file /bin/ls' -ex 'disassemble main'`
- Ghidra decompilation in pwndbg: `ctx-ghidra sym.foo()`

#### IDA

- Open strings window using `Shift + F12`. Can also open during debug mode.

### Resources

Awesome:

- https://medium.com/@vignesh4303/reverse-engineering-resources-beginners-to-intermediate-guide-links-f64c207505ed

Books:

- Reverse Engineering for Beginners
- Practical Reverse Engineering
- Practical Malware Analysis
- Linux Device Drivers
- Windows Internals
- Debugging with GDB
- The IDA Pro Book
- Radare2 Book
- Ghidra Book

Courses:

- RE101 - Malware Unicorn
- ARM reversing - Azeria

#### Todo

- Windows binaries (x64dbg)
- Kernel exploitation
- Browser explotation
- Z3 & angr framework
- Fuzzing (AFL/ASAN)

