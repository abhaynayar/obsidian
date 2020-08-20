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

