##  ► rev
### Debugging stripped binaries

- `(gdb) info file`
- `gef> entry`
- `gef> disas _start`

References
- https://felix.abecassis.me/2012/08/gdb-debugging-stripped-binaries/

### Assembly

Basics

- Byte (8 bits), word (16 bits) and double word (32 bits)
- RAX: 64-bit, EAX: 32-bit value, AX is the lower 16-bits, AL is the lower 8 bits, AH is the bits 8 through 15 (zero-based).
- Passing arguments: https://ctf101.org/binary-exploitation/what-are-calling-conventions/
    - 64-bit:
        - Linux: RDI, RSI, RDX, RCX, R8, R9
        - Windows: RCX, RDX, R8, R9, stack.
    - 32-bit: push arguments on to the stack (include them in the payload). ???
    - Arguments are pushed before the EIP in reverse order (right-to-left).
- `.bss` segment is used for statically-allocated variables that are not explicitly initialized to any value.
- Least significant three nibbles are the offset within a page (4KB) `3*4=12 => 2^12 = 4*(2^10)`

Instructions

- LEAVE: equivalent to `mov esp,ebp; pop ebp`
- CALL: push address of next instruction and change eip to given address.
- MOVS/MOVSB/MOVSW/MOVSD: move data from string to string.
- MOVSX: move with signed extension.
- BND: the return target should be checked against the bounds specified in the BND0 to BND3 registers
- ENDBR64:  it's an instruction that compilers put at the top of main in case the CPU supports the CET feature and is using it. If it's not supported, it's just a nop.
- Indirect branches are things like `call rax` that `_libc_start_main` uses to call your main, after `_start` passes it a pointer to your main.

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

## Radare2

Frequently used:

- List functions: `afl`
- Restart debugger: `ood`
- Seek to pc: `s rip` or `s eip`
- Continue till main `dcu main`
- Enter cmd in visual mode: `:`
- Print registers: `dr` or `dr=`

Todo

- Copy from disassembly: `TBD`
- Decompile current function: `TBD`

Command format

```
[.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ;
```

Some basic commands

- Block size `b` to seek using `s++` and `s--`
- Non-VA mode `-n` (by default it is VA mode)
- Print `p`: hex `px`, dissassembly `pd`
- Write `w`: hex `wx`, assembly `wa`, file `wf`
- Temporary offset `@`: example ` pd 5 @ 0x100000fce `
- Command history: `!~...`
- Examine `x`: example `x @ esi`
- Read registers: `dr` or `dr=`
- `=!`: the rest of the string is passed to the currently loaded IO plugin
- Multiple commands can be executed using `;` as in `px;dr=`
- To display sections and their addresses: `iS`

Visual mode

- Visual mode `V`: navigate `hjkl`, to quit `q`
- Graph mode: `VV` or `V` if already in visual
- Curses-like panels interface, accessible with `V!` or `!` if already in visual
- Use the '[' and ']' keys in visual mode to adjust the screen width
- Cursor mode `c`: to select bytes hold shift and navigate using `HJKL` 
- Overwrite bytes by pressing `i`
- Switch columns (hex, ascii) using `TAB`
- For different visual mode representations `p` or `P`

Command-line options

- Open r2 without file: `$r2 -`
- Open writeable `$r2 -w hello`
- Web server: `$r2 -c=H /bin/ls`
- Debug a program: `$r2 -d /bin/ls`
- Use an existing project file: `$r2 -p test`

Execute shell commands

- Using RCons API: `!ls`
- System call: `!!ls`

Redirection and grep

- Redirect stdout `px > out`
- Pipe into cmds `pd 10 | grep rcx`

Internal grep

```
pd 20~call
pd 20~call:0 ; get first row
pd 20~call:1 ; get second row
pd 20~call[0] ; get first column
pd 20~call[1] ; get second column
pd 20~call:0[0] ; grep the first column of the first row matching 'call'
```

Expressions

```
?vi 0x8048000
?vi 0x8048000+34
?vi 0x8048000+0x34
? 0x8048000+0x34
? 1+2+3-4\*3
```

Debugging

- To start debugging, use the command line option `-d`
- Along with the option you can use pid, path to binary, or gdb://
- `r2 -d /bin/ls` will stop in `ld.so` to prevent this you can:
    - Add an entry breakpoint in `~/.config/radare2/radare2rc`: `e dbg.bep=entry` or `e dbg.bep=main`
    - Use debug continue until main `dcu main` (sometimes main may execute before)
- To enter visual debugger mode use `Vpp`
    - Change views `p` or `P`
    - Step-into `s` or `F7`
    - Step-over `S` or `F8`
    - Continue `F9`
    - Cursor mode `c`
    - Set breakpoints `F2`
    - Radare commands prepending with `:`
- Some common debugger commands:

```
> d? ; get help on debugger commands
> ds 3 ; step 3 times
> db 0x8048920 ; setup a breakpoint
> db -0x8048920 ; remove a breakpoint
> dc ; continue process execution
> dcs ; continue until syscall
> dd ; manipulate file descriptors
> dm ; show process maps
> dmp A S rwx ; change permissions of page at A and size S
> dr eax=33 ; set register value. eax = 33
```

### Configuration

- The core reads `~/.config/radare2/radare2rc` while starting.
- To prevent radare2 from parsing this file at startup, pass it the `-N` option.
- From the command line: `$ radare2 -N -e scr.color=1 -e asm.syntax=intel -d /bin/ls`
- Within radare you can use the `e` or the `Ve` command to configure stuff.
- Use the `eco/ec/ecs` command for colours and themes.
- In visual mode use the `R` key to randomize colors or choose the next theme in the list.
- Get a list of configuration variables by entering `e` in your radare console: `e??~color`
- To list all the environment variables that matter to know where it will be looking for files: `r2 -H`


## How to be a full-stack reverse engineer
https://www.youtube.com/watch?v=9vKG8-TnawY&app=desktop

### Year 1

- Reversing by eldad-eilam
- Learn assembly
  - Hand decompile
  - Floating point
  - Vector code
- Reverse a game
  - 3D game, late 90s to mid 20s, custom engine
  - Reverse data archive format and write an unpacker
  - Reverse model format and write a renderer
- Compilers by aho-et-al (related book)
- Write a source-to-source compiler (scheme to python)
- Consider making ur own source language (not that hard)
- Write an assembler (no x86: pick mips, 32-bit arm, cil)

### Year 2

- Write compiler to assembly (subset of C)
- Reverse compilation techniques by sifia antes
- Write a bytecode decompiler (dalvik or cil)
  - Start with go-to based flows
  - Reconstruct flow based on graph
  - Transform to ssa for opt and clean
- Write a machine code decompiler (ARM to pseudo-C)
- Read the osdev wiki
- Write a toy kernel
  - C x86 protected
  - Text, input, basic graphics
- Read the osdev wiki
- Rewrite your kernel (in rust)
- Write a microkernel (L4)

### Year 3

- Write an interpreting emulator (NES,SNES,Gameboy,PS)
- Write a recompiling emulator
- Write an emulator for a black box platform

