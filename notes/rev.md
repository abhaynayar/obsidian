#  ► rev

## Tools:

- [Ghidra](https://ghidra-sre.org/)
- [IDA Pro](https://hex-rays.com/ida-pro/)
- [Radare2](https://rada.re/n/)

## Basics:
Translation process:

We often have multiple high-level source files to compile into a single
program, so we first compile each file into an object file and then we link
them using a linker.

To see the various steps in the compilation process, you can use certain
flags in gcc.

- To see the preprocessor stage: `gcc -E main.c`
- To see the assembly stage: `gcc -s main.c`
- To see the object stage: `gcc -c main.c`

When you compile a C file into an object file, the object file you get has
machine-level executable code. However, it needs to be linked first. So you
will see that such files are “relocatable” since the code itself is there
but it needs to be linked.

Linking:

Once these objects files are created, we use a linker to link them all into
a single executable. We may also link libraries that we have not coded
ourselves. These can be static libraries (.a), or they can be dynamic
libraries (.so) which still have unresolved symbols.

In the case of objects, you can check things to be relocated using:

```
$ readelf --relocs main.o
```

Symbols:

- ELF has DWARF. (in the binary)
- PE has PDB. (separate file)

Interpreter:

- Mapped into process's virtual memory.
- Performs relocations. (Lazy bindings)
- `ld-linux.so` and `ntdll.dll`


----

## ELF:

```
TODO
```

## Assembly

Basics:

- Byte (8 bits), word (16 bits) and double word (32 bits)
- RAX: 64-bit, EAX: 32-bit value, AX is the lower 16-bits, AL is the lower
  8 bits, AH is the bits 8 through 15 (zero-based).
- Passing arguments:
  https://ctf101.org/binary-exploitation/what-are-calling-conventions/
    - 64-bit:
        - Linux: RDI, RSI, RDX, RCX, R8, R9
        - Windows: RCX, RDX, R8, R9, stack.
    - 32-bit: push arguments on to the stack (include them in the payload).
    - Arguments are pushed before the EIP in reverse order (right-to-left).
- `.bss` segment is used for statically-allocated variables that are not
  explicitly initialized to any value.
- Least significant three nibbles are the offset within a page (4KB)
  `3*4=12 => 2^12 = 4*(2^10)`

Instructions:

- LEAVE: equivalent to `mov esp,ebp; pop ebp`
- CALL: push address of next instruction and change eip to given address.
- MOVS/MOVSB/MOVSW/MOVSD: move data from string to string.
- MOVSX: move with signed extension.
- BND: the return target should be checked against the bounds specified in
  the BND0 to BND3 registers
- ENDBR64:  it's an instruction that compilers put at the top of main in
  case the CPU supports the CET feature and is using it. If it's not
  supported, it's just a nop.
- Indirect branches are things like `call rax` that `_libc_start_main` uses
  to call your main, after `_start` passes it a pointer to your main.

Coding in assembly:

- 64-bit: `$ nasm -felf64 hello.asm && ld hello.o && ./a.out`
- 32-bit: `$ nasm -felf32 -g -F dwarf eip.asm && ld -m elf_i386 -o eip eip.o`
- In gdb, you can set breakpoint for the asm program using its labels, for example `b _start`
- [Running assembly in C](https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/asm3.md)
- We usually use `_start` in assembly similar to how we use `main` in C.
- Therefore we often break at `_start` within gdb.
- Use `fin` to continue until current function finishes.

## C

32-bit compilation:

```
$ sudo apt install gcc-multilib
$ gcc -m32 test.c -o test
```

Signedness:

- Make sure to use `%u` format specifier for unsigned data-types.
- The CPU does not care about signed and unsigned representations.
- We can see the difference while shifting integers and overflows.
- The conditional opcodes help differentiate in signedness.

Datatypes:

- For `uint_` related datatypes you need to `#include <stdint.h>`

## Debugging stripped binaries

- `(gdb) info file`
- `gef> entry`
- `gef> disas _start`

Further reading:
- https://felix.abecassis.me/2012/08/gdb-debugging-stripped-binaries/

## 64-bit code interpreted as 32-bit code.

- When you see a lot of `dec eax` or similar instructions, it might be 64-bit code interpreted as 32-bit code.
- We will see 32-bit code interpreted as 64-bit code when `cs` register is set to `0x33`:
    - https://www.malwaretech.com/2014/02/the-0x33-segment-selector-heavens-gate.html
    - http://scrammed.blogspot.com/2014/10/code-obfunscation-mixing-32-and-64-bit.html

## How to be a full-stack reverse engineer \[[1](https://www.youtube.com/watch?v=9vKG8-TnawY&app=desktop)\]

_Year 1:_

- [Reversing by Eldad-Eilam](https://www.amazon.in/dp/B07MMX3K3W/)
- Learn assembly:
  - Hand decompile
  - Floating point
  - Vector code
- Reverse a game:
  - 3D game, late 90s to mid 20s, custom engine.
  - Reverse data archive format and write an unpacker.
  - Reverse model format and write a renderer.
- [Compilers by Aho-et-al](https://www.amazon.in/dp/B0756XFTTW/)
- Write a source-to-source compiler. (Scheme to Python)
- Consider making ur own source language. (not that hard)
- Write an assembler. (not x86: pick mips, 32-bit ARM, CIL)

_Year 2:_

- Write compiler to assembly. (subset of C)
- [Reverse Compilation Techniques by Cristina Cifuentes](https://yurichev.com/mirrors/DCC_decompilation_thesis.pdf)
- Write a bytecode decompiler. (Dalvik or CIL)
  - Start with go-to based flows.
  - Reconstruct flow based on graph.
  - Transform to SSA for opt and clean.
- Write a machine code decompiler. (ARM to pseudo-C)
- Read the [osdev wiki](https://wiki.osdev.org/).
- Write a toy kernel.
  - C x86 protected.
  - Text, input, basic graphics.
- Read the osdev wiki.
- Rewrite your kernel. (in rust)
- Write a microkernel. (L4)

_Year 3:_

- Write an interpreting emulator. (NES,SNES,Gameboy,PS)
- Write a recompiling emulator.
- Write an emulator for a black box platform.
