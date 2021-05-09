<h2>Reverse-ing - TSG CTF</h2>
<p>12/07/2020</p>

<p>
We are given a binary file called <a href="reversing">reversing</a>. Below
I've written about some important things about the functions in the given
file.
</p>

<h3>reverse()</h3>

<p>
Length of the function: 0x6000b0 - 0x6000e4. This function swaps all
bytes in _start(). So if _start() looks like 0xabcdefgh, it is turned into
0xghefcdab. Everytime we jump into this function and go back we'll see
different code for _start(). This is a self modifying program. So it is
much easier to do a dynamic analysis. Below is the pseudocode which
performs the swap.
</p>

<pre>
for (ecx=0x6a; rcx &gt;=0; rcx--) {

    rdi = 0
    rdi = 0x6000e5 (starting address of _start)
    rdi += rcx ~&gt; 0x60014f (somewhere in the middle)

    rsi = 0
    rsi = 0x6001ba (towards the end of _start)
    rsi -= rcx ~&gt; 0x600150 (somewhere in the middle)

    dl = (byte*) rdi
    bl = (byte*) rsi
    (byte*) rsi = dl
    (byte*) rdi = bl

}
</pre>

<h3><_start()></h3>

<p>
Length of the function: 0x6000e5 - 0x6001ca. This function makes calls to
reverse() at almost every other line. rbx always points at reverse() we
call reverse() using <b>call rbx</b>. But I have removed the calls to rbx
below for code readability. rsi points at user input (size of user input
is 0x25=37 excluding newline). rdx starts decrementing from 0x25 to 0x00
(excluding newline). This function loops 0x25 times using rdx, going
through our input.
</p>

<pre>
15      mov     dl, 0x25   ; len(user_input) = 0x25
19      mov     rsi, rsp   ; rsi: user_input
24      xor     rdi, rdi   ; rdi=0: stdin
29      xor     rax, rax   ; rax=0
34      syscall            ; read(fd=rdi, buffer=rsi=user_input, count=rdx=0x25
38      dec     rdx        ; rdx--
43      xor     rcx, rcx   ; rcx=0
</pre>

<p>
Now once the init code in _start() is executed we fall into this loop.
This is the most important part of the program. Here we see that our input
is being moved into cl and first xored with one byte from memory then
added to another byte from memory. These come from <b>[rdx+0x600194]</b>.
You'll see that both the fragments are exactly the same. However there are
also calls to reverse() that I have omitted for clarity. Those calls swap
the contents of the bytes used to build the flag check.
</p>

<pre>
  48      mov     cl, BYTE PTR [rsi+rdx*1]
  53      xor     cl, BYTE PTR [rdx+0x600194]
  61      add     cl, BYTE PTR [rdx+0x600194]
  69      or      rdi, rcx
  74      dec     dl
  78      jns     0x600171 [_start+140]
-snip-
  140     mov     cl, BYTE PTR [rsi+rdx*1]
  145     xor     cl, BYTE PTR [rdx+0x600194]
  153     add     cl, BYTE PTR [rdx+0x600194]
  161     or      rdi, rcx
  166     sub     dl, 0x1
  171     jns     0x600115 [_start+48]
</pre>

<h3>_start(): after the loop</h3>

<p>... we branched after 78 (the calls to reverse are snipped)</p>

<pre>
82      mov     dl, 0x08
86      mov     al, 0x01
90      xor     rsi, rsi
95      mov     esi, 0x6001bb   ; [_start+214]: "correct\nwrong\n"
102     dec     edi
108 (!) js      0x60015c [_start+119] ; if we jump here, we win
112     mov     esi, 0x6001c3   ; [_start+222]: "wrong\n"
119     xor     rdi, rdi
124     inc     edi
128     syscall                 ; write "wrong\n"
???     mov     al, 0x3c
136     syscall                 ; exit
-snip-
</pre>

<p>
I didn't completely understand the check above, if someone understood this
please let me know. But using the same operation as the one performed in
the program, we see that the "right" bytes result in a zero once xored and
added.
</p>

<pre>
T       0x54    0xe4    0x48
S       0x53    0xd3    0x80
G       0x47    0xff    0x46
C       0x43    0x05    0xba
T       0x54    0x0f    0xa5
F       0x46    0x6b    0xd3
{       0x7b    0x7c    0xff

... this portion is evaled using the script below

}       0x7d    0xbb    0x32
\n      0x0a    0xdb    0x58
</pre>

<p>Solution script:</p>

<pre>
xors = [0x13, 0xff, 0xca, 0xd3, 0xff, 0xff, 0x31, 0x48, 0x72, 0x63, 0x2b, 0x19, 0x8c, 0xd3, 0xff, 0x25, 0xb2, 0x19, 0x5e, 0x61, 0xfb, 0xc1, 0xd3, 0xff, 0x00, 0x60, 0x00, 0xb0, 0xbb] 
adds = [0xc0, 0x31, 0x48, 0x1e, 0x65, 0x32, 0xa4, 0x88, 0xd3, 0xff, 0xe6, 0x89, 0x48, 0x5f, 0x7a, 0x84, 0x3b, 0xd3, 0xff, 0xd2, 0x31, 0x48, 0x4e, 0x36, 0xc9, 0xc5, 0xcf, 0x22, 0x32]

c=0
for i,j in zip(xors,adds):
    if c%2==1: print(chr(((0x100-i)^j)&amp;0xff), end='')
    else: print(chr(((0x100-j)^i)&amp;0xff), end='')
    c+=1
</pre>

Flag: <b>TSGCTF{S0r3d3m0_b1n4ry_w4_M4wa77e1ru}</b>
