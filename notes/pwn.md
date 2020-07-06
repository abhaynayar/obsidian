##  ► pwn
### Resources

- https://sidsbits.com/Path/
- https://ropemporium.com/
- https://overthewire.org/wargames/bandit/

### Notes

- Use `file` and `checksec` as initial checks on the binary.
- fgets() means you can use null bytes in your payload but not newlines.
- A newline is required at the end of your payload to cause the binary to process your input.
- `gets()` ends at newline or EOF, while `strlen()` stops at null byte.

### Finding function addresses

- `nm <binary> | grep ' t '`
- `pwndbg> info functions`

### Finding offset for overflow

`dmesg | tail`

### ROP tools

Finding gadgets
- `ropper -f <binary>`
- `ROPgadget --binary file_name > gadgets.txt`

Rejecting bad characters
- `ropper -b <badbytes>`
- `ROPgadget --badbytes <byte>`

Automatic ROP generation
- `ropper --chain "execve cmd=/bin/sh" -f <binary>`
- `ROPgadget --ropchain --binary <binary>`
- https://github.com/salls/angrop

### Getting a shell

- use a call to system() by passing shell command as the only argument (★ make sure to `call system` not simply jump to it, i.e., the call to system should already be there in the binary)
- use `syscall(x)`to call to`execve('/bin/sh', NULL,NULL)`
- find "x" from: `https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64`

### Writing to memory

1. look for gadgets like `mov [reg], reg ` (alternatively use something like`fgets`)
2. look for places to write to using `readelf -S <binary> ` or ` rabin2 -S <binary>`
   (don't forget to consider the size)
3. write the string to the address using the gadget found in step 1.
4. call system() with address of the written string.

★  In case you have leaked it, libc might already have the string

### Leaking libc.so.6

- Look into asis-ctf/full-protection.
- Leaking the address of functions
	- Get the address of `puts` using`pwndbg> x puts`
	- Get the address of `system` using `pwndbg> system`
	- Get the offset between them.
	- Get the address of `puts` while running the program.
	- Now, you can call `system` using address of `puts` and the offset you calculated earlier.
	- <https://sidsbits.com/Defeating-ASLR-with-a-Leak/>
	- <https://www.youtube.com/watch?v=evug4AhrO7o>
- Understand dynamic linking
  - https://ropemporium.com/guide.html (appendix A)
  - https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- Using a format string vulnerability (https://srikavin.me/blog/posts/5d87dbe86e58ed23d8620868-nactf-2019-loopy-0-1#Loopy--0-1)

#### Leaking stack canaries

```
TBD
```

### Format String Attacks

Reading from an arbritrary address

1. Get address of string to be read. `rabin2 -z <binary>`
2. Find the offset from the stack where the input is stored to do this `%x.`then `%x.%x.` then `%x.%x.%x.` and so on until you see the ascii values`25782e`.
3. Once you know the offset, store the address to be read at that offset by typing it in as the first thing in the buffer and then use the offset you found out to go read in that address: `python -c 'print "\xef\xbe\xad\xde%6$s"' | ./<binary>`

Offset notation: `%6$x`

#### Heap exploitation

- Least significant three nibbles are the offset within a page (4KB) `3*4=12 => 2^12 = 4*(2^10)`
- In an ELF file, towards the end is a section used as heap and `brk` is used to extend it.

Use after free

- There is no use after free vuln if the pointer is nulled out after `free`

----

### python

- Use package `struct` for converting string to binary data `struct.pack('II',10,10)` see format characters [here](https://docs.python.org/2/library/struct.html#format-characters).

### gdb
- How to set ASLR on on gdb (turns off every instance): `set disable-randomization off`

### pwntools

- Creating a template `pwn template ./<binary> --host 127.0.0.1 --port 1337`
- Debugging with gdb `io = gdb.debug('./<binary>', 'b main')`
- Passing commandline arguments `io = process(['./crackme','blah'])`
- Shell code `shellcode = asm(shellcraft.sh())`
- Cyclic padding
	- In the terminal `pwn cyclic 200`   ` pwn cyclic -l 0xdeadbeef`
	- In python: cyclic(length = None, alphabet = None, n = None)
		- length – The desired length of the list or None if the entire sequence is desired.
		- alphabet – List or string to generate the sequence over.
		- n (int) – The length of subsequences that should be unique.
- Also learn about fit()

