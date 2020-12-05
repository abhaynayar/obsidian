##  ► pwn
### Recon

1. file
2. strings
3. **readelf**
4. md5sum
5. objdump
6. checksec
7. ghex (patching,diffing)
8. ltrace (library calls)
9. strace (system calls)

### Tips

- Don't forget to pass arguments to registers in 64-bit instead of the stack.
- You may need to store the payload in some other section than stack, since stack is used by library functions.
- View symbols in text section: `$ nm -a empty | grep " t\| T"`
- **Make sure to point to `/bin/sh` and not the string value itself.**
- **Make sure to set your file as executable before running your tools.**
-  newline is required at the end of your payload to cause the binary to process your input.
- `fgets` means you can use null bytes in your payload but not newlines.
- `gets` ends at newline or EOF, while `strlen` stops at null byte.
- `nm <binary> | grep ' t '`
- `pwndbg> info functions`
- `dmesg | tail`
- `pwn cyclic`

### Format String Attacks
**Offset notation: `%6$x`**

**Learn about fmtstr in pwntools to automate format string exploits**
- *read-where* primitive: `%s` (for example, `AAAA%7$s` would return the value at the address 0x41414141).
- *write-what-where* primitive: `%n`
- write one byte at a time: `%hhn` 

Reading from an arbritrary address

1. Get address of string to be read. `rabin2 -z <binary>`
2. Find the offset from the stack where the input is stored: `%x.`then `%x.%x.` then `%x.%x.%x.` and so on until you see the ascii values`25782e`
3. Once you know the offset, store the address to be read at that offset by typing it in as the first thing in the buffer and then use the offset you found out to go read in that address: `python -c 'print "\xef\xbe\xad\xde%6$s"' | ./<binary>`

Writing to an arbritrary address

- CSI (VIT) CTF 2020 - global warming
- NaCTF 2019 - format1
- NaCTF 2020 - format


### GOT and PLT

- The first time you make a call to a function like `printf` that resides in a dynamic library, it calls `printf@plt`
- Within `printf@plt` it jumps into `printf@got.plt` that is we jump to whatever address is stored in the GOT.
- From there we go to `_dl_runtime_resolve` which is in the dynamic linker `ld.so` which helps set up external references to libc.
- Next time onwards we directly jump to `printf` from the GOT.
- Since dynamically linked libraries update and also due to ASLR, we cannot hardcode addresses of functions that are run through the libraries.
- So we use relocation which is done by the dynamic linker called `ld-linux.so` run before any code from libc or your program.

Sections required by relocation

1. `.got`: table of offsets filled by the linker for external tables.
2. `.plt`: stubs to look up addresses in .got section (jump to the right address or ask the linker to resolve it).

How relocation happens

1. When you call a library function for the first time, it calls the `.plt` section function within your binary.
2. In the `.plt` we have jump to an address in `.got` which has been filled by the linker with the address of the given function in libc.

Lazy binding

- Got gets the actual function address after the first call).
- Before lazy binding the GOT entry points back into the PLT.

GOT overwrite

- **Look into pico18/echo-back**
- https://www.youtube.com/watch?v=kUk5pw4w0h4
- https://nuc13us.wordpress.com/2015/09/04/format-string-exploit-overwrite-got/
- Find the address of GOT entry of a function that is going to be called.
- Use arbritrary write primitive to change that to some other function's got address.

References

- https://ropemporium.com/guide.html (appendix A)
- https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- https://refspecs.linuxbase.org/LSB\_3.1.1/LSB-Core-generic/LSB-Core-generic/specialsections.html
- http://www.infosecwriters.com/text\_resources/pdf/GOT\_Hijack.pdf
- https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- https://stackoverflow.com/questions/43048932/why-does-the-plt-exist-in-addition-to-the-got-instead-of-just-using-the-got


### Leaking libc, functions, canaries

- NaCTF 2020: dROPit

**If you can leak any one function, look into the last three nibbles and search for it on https://libc.blukat.me**

Using format string attacks

- http://abhaynayar.com/ctf/asis.html
- https://srikavin.me/blog/posts/5d87dbe86e58ed23d8620868-nactf-2019-loopy-0-1#Loopy--0-1 

Leaking libc base

- See pico2018/got-2-learn-libc
- http://abhaynayar.com/ctf/asis.html
- First somehow get the address of puts during runtime.
- One way to do that is to use puts itself to print its address by using a buffer overflow (+ROP chain).
- Then subtract it from the puts offset from the given libc binary.
- **Remember to use given library / your library depending on where you're testing.**
- libc.address = puts\_runtime - libc.symbols['puts']

Leaking functions

- Similar to leaking libc base, but with a function.
- https://sidsbits.com/Defeating-ASLR-with-a-Leak/
- https://www.youtube.com/watch?v=evug4AhrO7o
- Get the address of `puts` using `(gdb) x puts`
- Get the address of `system` using `(gdb) system`
- Get the offset between them.
- Get the address of `puts` while running the program.
- Now, you can call `system` using address of `puts` minus the offset you calculated earlier.

### Return oriented programming

Getting a shell

- Use a call to `system` by passing shell command as the only argument.
- **Make sure to `call system` not simply jump to it.** (update: you don't need to call system, we need to align the stack so use an extra `ret` gadget).
- If you want to directly jump to it, make sure to append a dummy return address and a parameter after it: `payload="A"*offset + system + "AAAA" + binsh`
- Use `syscall(x)`to call to`execve('/bin/sh', NULL,NULL)`
- exec syscall on 32bit: 0x0b, exec syscall on 64bit: 0x3b.
- find "x" from: `https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64`

Writing to memory (in case you want "/bin/sh")

1. Look for gadgets like `mov [reg], reg ` (alternatively use something like`fgets`)
2. Look for places to write to using `readelf -S <binary> ` or ` rabin2 -S <binary>` (don't forget to consider the size)
3. Write the string to the address using the gadget found in step 1.
4. Call `system` with address of the written string.

### Heap exploitation
#### Nightmare

Glibc version

- When you are working on a heap challenge, make sure you are using the right libc file using `LD_PRELOAD`
- When you attempt to use `LD_PRELOAD` to have a binary use a specific libc file, you might find an issue if the linker's are not compatible.

Chunks

```
gef> heap chunks
```

- Every chunk has a heap header/metadata
- For x64: 0x10 bytes (2x64 bits) before chunk start
- For x86: 0x08 bytes (2x32 bits) before chunk start
- The first word contains previous chunk size (zero if not set).
- The second word contains current chunk size (including heap header/metadata and rounding up for better binning).
- For the current size word, we have the 3 LSBs as flags:
    - 0x1: previous chunk in use
    - 0x2: chunk obtained through mmap()
    - 0x4: chunk obtained from outside main area
    
Bins

```
gef> heap bins
```

- When chunks are freed they are added to bin lists.
- These chunks can be used later, for performance benefits.

Fastbins

- 7 "linked lists" indexed by `idx`
- x64 sized range from 0x20 to 0x80
- Points to the next chunk in list.
- Chunks are inserted into the fast bin head first (LIFO).

Tcachebins

- New type of binning mechanism introduced in libc version 2.26
- Tcache is specific to each thread, so each thread has its own tcache.
- Speeds up performance as malloc won't have to lock the bin to edit it.
- Stored like a Fast Bin - LIFO linked list.
- Can only hold 7 chunks per list at a time.
- There are a total of 64 tcache lists, with idx values ranging from 0-63, for chunk sizes between 0x20-0x410.
- It's the fast bin with less checks (and can take in somewhat larger chunks).

Unsorted, large and small bins

- Their lists live together in the same array using the following indexes:
    - Unsorted bins: 1 (0x01) (0x00 is not used)
    - Small bins: 62 (0x02 to 0x3f)
    - Large Bin: 63 (0x40 to 0x7e)
- Chunks that are not inserted into fastbins or tcachebins are first inserted into unsorted bins.
- Chunks will remain there until they are sorted. This happens when another call is made to malloc. It will then check through the Unsorted Bin for any possible chunks that can meet the allocation.
- It will check if there are chunks that belong in one of the small / large bin lists. If there are it will move those chunks to the appropriate bins.
- Small bins on x64 consists of chunk sizes under 0x400 (1024 bytes), and on x86 consists of chunk sizes under 0x200 (512 bytes)
- Large bins consists of values above those of small bins.
- All three chunks have two pointers `fwd` and `bk` as the first thing in the content section because they are doubly linked lists.
- The large chunk has two more pointers `fwd_nextsize` and `bk_nextsize` to point to next chunk of *different* size. It's kind of like a skip list.
- Chunks in the large bin are stored largest to smallest.

Consolidation

- Heap is fragmented into a lot of smaller pieces.
- malloc tries to allocate a large chunk of space.
- Will have to use different memory for it, and effectively waste space.
- Consolidation tries to fix this by merging adjacent freed chunks together, into larger freed chunks.

Top chunk

- A large heap chunk that holds currently unallocated data.
- Allocating large chunks of memory from the kernel, and managing memory allocations from that memory is a lot more efficient than requesting memory from the kernel each time.
- malloc first looks into the bins, then into the top chunk.

Top chunk consolidation

- A lot of heap attacks target a bin list.
- For that we need freed chunks in the bins lists.
- Consolidation with the top chunk can prevent that.
- Allocate a small chunk between freed chunks and top chunk.

Main arena

- Data structure used for managing heap memory.
- Contains the head pointers for the bin lists.

```
+----------------+-------------------------+--------------------+
| Bug            | Bin attack              | House              |
+----------------+-------------------------+--------------------+
| Double free    | Fastbin attack          | House of Spirit    |
| Heap overflow  | tcache attack           | House of Lore      |
| Use after free | Unsorted bin attack     | House of Force     |
|                | Small/Large bin attack  | House of Einherjar |
|                | Unsafe unlink (?)       | House of Orange    |
+----------------+-------------------------+--------------------+
```

#### Max Kamper

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

Bins

- There is also an array of pointers called bins.
- They point to doubly linked lists of chunks.
- These are chunks that were allocated and then freed.

Using gdb wrappers for heap

- Use `vmmap` to see heap region.
- Heap will only come up once `malloc` has been used.
- Use `heap chunks` in gef or `vis_heap_chunks` in pwndbg to see the chunks in heap.

```
+-----------------+
|   stack         |
+-----------------+
|   libraries     |
+-----------------+
|   heap          |
+-----------------+
|   application   |
+-----------------+
```

#### Gynvael Coldwind

- User mode programs can ask for one page of memory from the kernel mode.
- `printf` requests a page using mmap because standard output is buffered.
- Towards the end of an elf file is a section used as heap and `brk` is used to extend it.
- `mmap` is used to get virtual memory pages from the OS (on windows it's called virtual alloc).
- This is why we need heap, since we don't want to waste an entire page everytime we need something.
- When malloc-ing a lot of stuff, if the pages of allocation change it means a new heap is created (?).

### Fuzzing

- To get source from apt `apt-get source binutils`
- To build binutils `CC=afl-gcc ./configure` then `make`

### ARM exploitation

- ARM mode has 4 byte instruction alignment.
    - Can’t jump in the middle of instructions.
- THUMB mode has 2 byte instruction alignment.
    - When ROPing there’s usually more THUMB gadgets that will be of use due to the 2 byte alignment.
- Because of 2 & 4 byte instruction alignment, the lowest bit of the program counter (eg r15) will never be set.
- This bit is re-purposed to tell the processor if we are in THUMB mode or ARM mode.

Sources:

- RPISEC MBE

### Windows Exploitation

- The executable format on Windows is .EXE instead of Linux ELF’s
- Libraries are .DLL, like Linux .so (eg: MSVCRT.dll is like libc)
- If you’re going to get rolling on Windows, try to pick up skills debugging with WinDbg **EARLY**.
- Raw syscalls are virtually never seen in native windows applications or libraries.
- So instead of using syscalls,  an exploit will almost always use existing imported functions.
- ntdll.dll – the 'Native API' wraps all the syscalls for the given version of Windows, is pretty low level stuff (the only process that must be loaded).
- kernel32.dll – the 'Win32 API' more familiar high level stuff OpenFile(), ReadFile(), CreateProcess(), LoadLibrary(), GetProcAddress().

Sources:

- RPISEC MBE

### Tools

#### radare2

- Search for a string: `/ string_content`
- Seek: `s 0xdeadbeef`
- Print in hex: `px`
- Change to write mode: `oo+`
- Write bytes: `w hello, world`

#### gdb/gef

- To change register values `set $sp += 4`
- To search for string in memory `gef> grep asdf`
- https://sourceware.org/gdb/onlinedocs/gdb/Hooks.html
- To calculate stuff inside gdb `p 1+2`
- Delete all breakpoints using `d`
- Delete breakpoint by number using `d 1`
- `jump +1` jumps to the next line line i.e. skipping the current line. Can be used when stuck in `rep`
- `tbreak +1` to set a temporary breakpoint at the jump target.
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
- Disassemble function from the command line: `$ gdb -batch -ex 'file /bin/ls' -ex 'disassemble main'` or `gdb -q ./a.out 'disass main'`
- Ghidra decompilation in pwndbg: `ctx-ghidra sym.foo()`
- Execute python in gdb: `(gdb) python print('asdf')`

#### IDA

- Open strings window using `Shift + F12`. Can also open during debug mode.
- Change between basic and graphic mode (space bar)
- Rename variables: (n)
- Comment –Side: (:), (;) –Above/below: (ins)
- Convert const formats: (right-click)
- Cross-reference: (x)
- Change to array: (a)
- IDA-Options-General-auto comment
- IDA-Options-General-opcode bytes 8 

#### pwntools

- Searching for strings: `payload += p64(next(libc.search(b'/bin/sh')))`
- `flat(*args, preprocessor = None, length = None, filler = de_bruijn(), word_size = None, endianness = None, sign = None)` -> str. Strings are inserted directly while numbers are packed using the pack() function: `flat({32:'1337'})`
- To only see error logs: `context.log_level = 'error'`
- Need to use `io.interactive` or `io.wait` (?)
- Use `recv()` to receive everything up till that point.
- While writing your exploit script keep `io.interactive()` at the end and keep adding sends and receives before it.
- Sometimes remote connection might be close due to an error in your python code (such as bytes != strings).
- For passing args: `io = process(['./chall','AAAA'])` or `io = gdb.debug(['./chall','AAAA'], 'b main')`
- Creating a template `pwn template ./<binary> --host 127.0.0.1 --port 1337`
- Debugging with gdb `io = gdb.debug('./<binary>', 'b main')`
- Passing commandline arguments `io = process(['./crackme','blah'])`
- Shell code `shellcode = asm(shellcraft.sh())`

Cyclic padding in pwntools

Using terminal

```
$pwn cyclic 200
pwn cyclic -l 0xdeadbeef
```

Using python

```python
x = 4 #x=8 for 64-bit
io.sendline(cyclic(200, n=x))
io.wait()
core = io.corefile
offset = cyclic_find(core.read(core.esp, x), n=x) #rsp for 64 bit
offset -= x # wherever the sequence is found, we replace it
```

ROP in pwntools

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

rop = offset + p64(pie+pop_rdi) + p64(pie+puts_got) + p64(pie+puts_plt) + p64(pie+main_plt)
```

### Resources

Courses

- ARM reversing - Azeria
- RE101 - Malware Unicorn
- [Ultimate guide to reversing](https://medium.com/@vignesh4303/reverse-engineering-resources-beginners-to-intermediate-guide-links-f64c207505ed)
- https://ropemporium.com/
- https://sidsbits.com/Path/
- https://overthewire.org/wargames/narnia

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

