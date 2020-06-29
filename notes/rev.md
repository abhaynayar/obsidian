##  ► rev
### Tools
#### GDB

- https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf
- Address of a variable ```p &var```
- Changing variable values ```set var <variable_name>=<value>```
- Disable SIGALRM ``` handle SIGALRM ignore ```
- Remove all breakpoint using `d`

#### IDA

- Open strings window using ```Shift + F12```. Can also open during debug mode.

### Assembly

- Running a program ```nasm -felf64 hello.asm && ld hello.o && ./a.out```
- Byte (8 bits), word (16 bits) and double word (32 bits)
- RAX: 64-bit, EAX: 32-bit value, AX is the lower 16-bits, AL is the lower 8 bits, AH is the bits 8 through 15 (zero-based)
- What does ```call``` do?
    1. Pushes address of next instruction on to the stack
    2. Changes ```eip``` to given address
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

### Resources
#### Awesome

- https://medium.com/@vignesh4303/reverse-engineering-resources-beginners-to-intermediate-guide-links-f64c207505ed

#### Books

- Practical Malware Analysis
- Practical Reverse Engineering
- Reverse Engineering for Beginners
- Windows Internal Book
- Linux Device Drivers
- Debugging with GDB
- Radare2 Book

#### Courses

- RE101 - Malware Unicorn
- ARM reversing - Azeria

#### Learn

- Fuzzing (AFL/ASAN)
- Kernel exploitation
- Browser explotation
- Windows binaries (x64dbg)
- z3 `pip install z3-solver`
- angr https://github.com/angr/angr

