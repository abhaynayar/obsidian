## Radare2 Book
### First steps

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

Visual mode

- Visual mode `V`: navigate `HJKL`, to quit `q`
- Use the '[' and ']' keys in visual mode to adjust the screen width
- Cursor mode `c`: to select bytes hold shift and navigate using `HJKL` 
- Overwrite bytes by pressing `i`
- Switch columns (hex, ascii) using `TAB`
- For different visual mode representations `p` or `P`
- Curses-like panels interface, accessible with `V!`

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

