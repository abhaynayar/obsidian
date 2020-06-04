##  ► rev

### r2book

- seek `s`
- block size `b`
- non-VA mode `-n`
- print `p`: hex `px`, dissassembly `pd`
- write `w`: hex `wx`, assembly `wa`, file `wf`

visual mode
- visual mode `V` (to quit `q`)
- navigation `HJKL`
- cursor mode `c`: hold shift and navigate using `HJKL` to select bytes
- overwrite bytes by pressing `i`
- switch columns (hex, ascii) using `TAB`
- for different visual mode representations `p` or `P`
- curses-like panels interface, accessible with `V!`

command-line options
- open r2 without file: `$r2 -`
- run script before interactive prompt: `$r2 -i patch.r2 target.bin`
- run command without interactive prompt: `$r2 -qc ij hi.bin > imports.json`
- set configuration variables: `$r2 -e scr.color=0 blah.bin`
- debug `$r2 -d ls`
- use an existing project file `$r2 -p test`

commands
- general format: `[.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ;`
- commands are identified by a single case-sensitive character [a-zA-Z]
- execute command in shell context `!` for cmd callback use `=!`

### Resources
- <https://wiki.bi0s.in/reversing/asm/>

### Learn
- z3 ```pip install z3-solver```
- qira-1.3 <https://github.com/geohot/qira>
- angr <https://github.com/angr/angr>
- BAP <https://github.com/BinaryAnalysisPlatform/bap>

### Tools
- GDB
- IDA
- Ghidra
- Cutter

### Initial checks
- ```file <binary>```
- ```strings <binary>```
- ```./<binary>```

### Assembly Language
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

- leave is exactly equivalent to
```
mov   esp, ebp
pop   ebp
```

- When assembly gets a bit hard to do by hand use <https://carlosrafaelgn.com.br/asm86/>
- Take reference from <https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/asm3.md>

### GDB
- <https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf>
- Address of a variable ```p &var```
- Changing variable values ```set var <variable_name>=<value>```
- Disable SIGALRM ``` handle SIGALRM ignore ```
- Learn about fuzzing

### IDA
- Open strings window using ```Shift + F12```. Can also open during debug mode.
