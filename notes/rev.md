##  ► rev

### C

Signed-ness

- Make sure to use `%u` format specifier for unsigned data-types.
- The CPU does not care about signed and unsigned representations.
- We can see the difference while shifting integers and overflows.

### Assembly

- Running a program `nasm -felf64 hello.asm && ld hello.o && ./a.out`
- Byte (8 bits), word (16 bits) and double word (32 bits)
- RAX: 64-bit, EAX: 32-bit value, AX is the lower 16-bits, AL is the lower 8 bits, AH is the bits 8 through 15 (zero-based)
- What does `call` do?
    1. Pushes address of next instruction on to the stack
    2. Changes `eip` to given address
- Passing arguments
    - _64 bit_ : first four arguments rdi, rsi, rdx, rcx
    - _32 bit_ : push arguments on to the stack (include them in the payload)
    - Arguments are pushed on to the stack in reverse order:


```
; maybe this is wrong
asm0(0xd8,0x7a)
[ebp+0x8] = 0x7a
[ebp+0xc] = 0xd8

; args are pushed while in the previous stack frame
; ebp + x means we are moving upwards, i.e., opposite
; to the direction of growth of the stack

asm2(0x6,0x28)
[ebp+0xc] = 0x28
[ebp+0x8] = 0x6
```

`leave` is equivalent to:

```
mov   esp, ebp
pop   ebp
```

Refer:

- https://carlosrafaelgn.com.br/asm86
- https://github.com/Dvd848/CTFs/blob/master/2019\_picoCTF/asm3.md
- https://github.com/abhaynayar/ctf/tree/master/labs/rev/asm\_analysis

### Tools
#### GDB

- Examine general format: `x/nfu addr`
- To examine a double word (giant): `x/xg addr`
- Changing variable values `set var <variable_name>=<value>`
- Disable SIGALRM `handle SIGALRM ignore`
- Remove all breakpoints using `d`
- Address of a variable `p &var`
- Disassemble function from the command line: `gdb -batch -ex 'file /bin/ls' -ex 'disassemble main'`

https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf

#### IDA

- Open strings window using `Shift + F12`. Can also open during debug mode.

### Resources
#### Awesome

- https://medium.com/@vignesh4303/reverse-engineering-resources-beginners-to-intermediate-guide-links-f64c207505ed

#### Books

- Practical Malware Analysis
- Practical Reverse Engineering
- Reverse Engineering for Beginners
- Mastering Reverse Engineering
- Windows Internal Book
- Linux Device Drivers

Tools

- Debugging with GDB
- The IDA Pro Book
- Radare2 Book
- Ghidra Book

#### Courses

- RE101 - Malware Unicorn
- ARM reversing - Azeria

#### Learn

- Fuzzing (AFL/ASAN)
- Kernel exploitation
- Browser explotation
- Z3 & angr framework
- Windows binaries (x64dbg)

