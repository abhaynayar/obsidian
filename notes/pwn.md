# ► pwn
## Writeups by topic

Leaking libc:
- [loopy - NaCTF 2021](https://ctftime.org/task/9312)
- [dROPit - NaCTF 2020](https://ctftime.org/task/13818)
- Full Protection - ASIS CTF Quals 2020
- got-2-learn-libc - Pico CTF 2018

Format string attacks (Writing to an arbritrary address):
- global warming - CSI (VIT) CTF 2020
- format1 - NaCTF 2019
- format - NaCTF 2020

GOT overwrite:
- echo-back - Pico CTF 2018

## Resources

Courses:
- https://ropemporium.com/
- https://sidsbits.com/Path/
- https://overthewire.org/wargames/narnia

## Recon

Run these commands on the given binary:

1. file
2. strings
3. readelf
4. md5sum
5. objdump
6. checksec
7. ghex (patching,diffing)
8. ltrace (library calls)
9. strace (system calls)

## Tips

- Don't forget to pass arguments to registers in 64-bit instead of the
  stack.
- You may need to store the payload in some other section than the stack,
  since stack is used by library functions.
- View symbols in text section: `$ nm -a empty | grep " t\| T"`
- **Make sure to point to `/bin/sh` and not the string value itself.**
- **Make sure to set your file as executable before running your tools.**
- Newline is required at the end of your payload to cause the binary to
  process your input.
- `fgets` means you can use null bytes in your payload but not newlines.
- `gets` ends at newline or EOF, while `strlen` stops at null byte.
- `nm <binary> | grep ' t '`
- `pwndbg> info functions`
- `dmesg | tail`
- `pwn cyclic`

## Format String Attacks
**Offset notation: `%6$x`**

- *read-where* primitive: `%s`
- for example, `AAAA%7$s` would return the value at address: `0x41414141`
- *write-what-where* primitive: `%n`
- write one byte at a time: `%hhn` 

Reading from an arbritrary address:

1. Get address of string to be read. `rabin2 -z <binary>`
2. Find the offset from the stack where the input is stored: `%x.`then
   `%x.%x.` then `%x.%x.%x.` and so on until you see the ascii
   values`25782e`
3. Once you know the offset, store the address to be read at that offset by
   typing it in as the first thing in the buffer and then use the offset
   you found out to go read in that address: `python -c 'print
   "\xef\xbe\xad\xde%6$s"' | ./<binary>`

## GOT and PLT

- The first time you make a call to a function like `printf` that resides
  in a dynamic library, it calls `printf@plt`
- Within `printf@plt` it jumps into `printf@got.plt` that is we jump to
  whatever address is stored in the GOT.
- From there we go to `_dl_runtime_resolve` which is in the dynamic linker
  `ld.so` which helps set up external references to libc.
- Next time onwards we directly jump to `printf` from the GOT.
- Since dynamically linked libraries update and also due to ASLR, we cannot
  hardcode addresses of functions that are run through the libraries.
- So we use relocation which is done by the dynamic linker called
  `ld-linux.so` run before any code from libc or your program.

Sections required by relocation:

1. `.got`: table of offsets filled by the linker for external tables.
2. `.plt`: stubs to look up addresses in .got section (jump to the right
   address or ask the linker to resolve it).

How relocation happens:

1. When you call a library function for the first time, it calls the `.plt`
   section function within your binary.
2. In the `.plt` we have jump to an address in `.got` which has been filled
   by the linker with the address of the given function in libc.

Lazy binding:

- Got gets the actual function address after the first call).
- Before lazy binding the GOT entry points back into the PLT.

GOT overwrite:

- https://www.youtube.com/watch?v=kUk5pw4w0h4
- https://nuc13us.wordpress.com/2015/09/04/format-string-exploit-overwrite-got/
- Find the address of GOT entry of a function that is going to be called.
- Use arbritrary write primitive to change that to some other function's
  GOT address.

References:

- https://ropemporium.com/guide.html (appendix A)
- https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- https://refspecs.linuxbase.org/LSB\_3.1.1/LSB-Core-generic/LSB-Core-generic/specialsections.html
- http://www.infosecwriters.com/text\_resources/pdf/GOT\_Hijack.pdf
- https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- https://stackoverflow.com/questions/43048932/why-does-the-plt-exist-in-addition-to-the-got-instead-of-just-using-the-got

## Leaking libc, functions, canaries

Leaking libc base:

- First somehow get the address of puts during runtime.
- One way to do that is to use puts itself to print its address by using a
  buffer overflow (+ROP chain).
- Then subtract it from the puts offset from the given libc binary.
- **Remember to use given library / your library depending on where you're
  testing.**
- libc.address = puts\_runtime - libc.symbols['puts']

Leaking functions:

- Similar to leaking libc base, but with a function.
- https://sidsbits.com/Defeating-ASLR-with-a-Leak/
- https://www.youtube.com/watch?v=evug4AhrO7o
- Get the address of `puts` using `(gdb) x puts`
- Get the address of `system` using `(gdb) system`
- Get the offset between them.
- Get the address of `puts` while running the program.
- Now, you can call `system` using address of `puts` minus the offset you
  calculated earlier.

**If you can leak any one function, look into the last three nibbles and
search for it on https://libc.blukat.me**

## Return-oriented programming

Getting a shell:

- Use a call to `system` by passing shell command as the only argument.
- **Make sure to `call system` not simply jump to it.** (update: you don't
  need to call system, we need to align the stack so use an extra `ret`
  gadget).
- If you want to directly jump to it, make sure to append a dummy return
  address and a parameter after it: `payload="A"*offset + system + "AAAA" +
  binsh`
- Use `syscall(x)`to call to`execve('/bin/sh', NULL,NULL)`
- exec syscall on 32bit: 0x0b, exec syscall on 64bit: 0x3b.
- find "x" from:
  `https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64`

Writing to memory: (in case you want "/bin/sh")

1. Look for gadgets like `mov [reg], reg ` (alternatively use something
   like`fgets`)
2. Look for places to write to using `readelf -S <binary> ` or ` rabin2 -S
   <binary>` (don't forget to consider the size)
3. Write the string to the address using the gadget found in step 1.
4. Call `system` with address of the written string.

## Fuzzing

- To get source from apt `apt-get source binutils`
- To build binutils `CC=afl-gcc ./configure` then `make`

## ARM exploitation

- ARM mode has 4 byte instruction alignment.
  - Can’t jump in the middle of instructions.
- THUMB mode has 2 byte instruction alignment.
  - When ROPing there’s usually more THUMB gadgets that will be of use due
    to the 2 byte alignment.
- Because of 2 & 4 byte instruction alignment, the lowest bit of the
  program counter (eg r15) will never be set.
- This bit is re-purposed to tell the processor if we are in THUMB mode or
  ARM mode.

## Tools
### radare2

- Search for a string: `/ string_content`
- Seek: `s 0xdeadbeef`
- Print in hex: `px`
- Change to write mode: `oo+`
- Write bytes: `w hello, world`

### gdb/gef

- To change register values `set $sp += 4`
- To search for string in memory `gef> grep asdf`
- https://sourceware.org/gdb/onlinedocs/gdb/Hooks.html
- To calculate stuff inside gdb `p 1+2`
- Delete all breakpoints using `d`
- Delete breakpoint by number using `d 1`
- `jump +1` jumps to the next line line i.e. skipping the current line. Can
  be used when stuck in `rep`
- `tbreak +1` to set a temporary breakpoint at the jump target.
- `step` steps into subroutines, but `next` will step over subroutines.
- `step` and `stepi` (and the `next` and `nexti`) are distinguishing by
  "line" or "instruction" increments.
- In most of my use-cases I need `nexti` (short `ni`)
- To find address of a variable: `(gdb) p &var`
- While printing variables if it is an unknown type use `(gdb) p (int)var`
- Break at an offset from function `(gdb) b*main+128`
- To get out of current function use `(gdb) finish`
- To list all functions `(gdb) info functions regex`
- To learn the relationship between higher level code and assembly better,
  use the -ggdb option while compilint. 
- When GDB opens via debug(), it will initially be stopped on the very
  first instruction of the dynamic linker (ld.so) for dynamically-linked
  binaries.
- To view the source (and provide more debugging info) use -ggdb flag while
  compiling with `gcc`
- How to set ASLR on on gdb (turns off every instance): `set
  disable-randomization off`
- How to print strings when you have their name (symbol)?: `p str` then
  `x/s`
- Examine general format: `x/nfu addr`
- To examine a double word (giant): `x/xg addr`
- Changing variable values `set var <variable_name>=<value>`
- Disable SIGALRM `handle SIGALRM ignore`
- Disassemble function from the command line: `$ gdb -batch -ex 'file
  /bin/ls' -ex 'disassemble main'` or `gdb -q ./a.out 'disass main'`
- Ghidra decompilation in pwndbg: `ctx-ghidra sym.foo()`
- Execute python in gdb: `(gdb) python print('asdf')`

### IDA

- Open strings window using `Shift + F12`. Can also open during debug mode.
- Change between basic and graphic mode (space bar)
- Rename variables: (n)
- Comment –Side: (:), (;) –Above/below: (ins)
- Convert const formats: (right-click)
- Cross-reference: (x)
- Change to array: (a)
- IDA-Options-General-auto comment
- IDA-Options-General-opcode bytes 8 

### pwntools

- Searching for strings: `payload += p64(next(libc.search(b'/bin/sh')))`
- `flat(*args, preprocessor = None, length = None, filler = de_bruijn(),
  word_size = None, endianness = None, sign = None)` -> str. Strings are
  inserted directly while numbers are packed using the pack() function:
  `flat({32:'1337'})`
- To only see error logs: `context.log_level = 'error'`
- Need to use `io.interactive` or `io.wait` (?)
- Use `recv()` to receive everything up till that point.
- While writing your exploit script keep `io.interactive()` at the end and
  keep adding sends and receives before it.
- Sometimes remote connection might be close due to an error in your python
  code (such as bytes != strings).
- For passing args: `io = process(['./chall','AAAA'])` or `io =
  gdb.debug(['./chall','AAAA'], 'b main')`
- Creating a template `pwn template ./<binary> --host 127.0.0.1 --port
  1337`
- Debugging with gdb `io = gdb.debug('./<binary>', 'b main')`
- Passing commandline arguments `io = process(['./crackme','blah'])`
- Shell code `shellcode = asm(shellcraft.sh())`

Cyclic padding in pwntools:

Using terminal:

```
$pwn cyclic 200
pwn cyclic -l 0xdeadbeef
```

Using Python:

```python
x = 4 #x=8 for 64-bit
io.sendline(cyclic(200, n=x))
io.wait()
core = io.corefile
offset = cyclic_find(core.read(core.esp, x), n=x) #rsp for 64 bit
offset -= x # wherever the sequence is found, we replace it
```

ROP in pwntools:

```python
# finding gadgets
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
```

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

rop = offset + p64(pie+pop_rdi) + p64(pie+puts_got) + p64(pie+puts_plt) +
p64(pie+main_plt)
```
