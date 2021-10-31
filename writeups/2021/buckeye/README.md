# Buckeye CTF

## rev
### BASIC

```
Get ready to go back to high school cause we're breaking out those graphing
calculators! The ROM file is just to help run the challenge, you shouldn't
have to reverse any of it. P.S. Remember that flags are case sensitive!
```

We are given two files in this challenge: `BASIC.8xp` and `ti84plus.rom`.

The first file is apparently a program that can be run on a TI calculator
while the second file is the ROM for the calculator itself. We don't need
to analyze the second file.

We first install this tool to decompile the `.8xp` files:

```
$ pip3 install basically-ti-basic
```

Then, with this command, we decompile the program:

```
$ basically-ti-basic -d -i BASIC.8xp -o BASIC.txt
```

Looking at the program, I've extracted some key lines:

```
"F4X67ENQPK0{MTJRHL}O3G59UB–ZAWV8S2YI1CD"→Str2
{26,25,38,10,6,35,6,12,13,2,14,17,27,38,18,29,23,23,27,30,2,33,27,26,11,16,37,7,22,19}→l4

-snip-

For I,1,30,1)
If sub(Str7,I,1)!=sub(Str2,l4(I),1)
```

It can be seen that it is a simple mapping between an array of indices and
a string. We can now write a simple Python program to get the target
string.

```
Str2 = "F4X67ENQPK0{MTJRHL}O3G59UB–ZAWV8S2YI1CD"
l4 = [26, 25, 38, 10, 6, 35, 6, 12, 13, 2, 14, 17, 27, 38, 18, 29, 23, 23,
        27, 30, 2, 33, 27, 26, 11, 16, 37, 7, 22, 19]


ans = ""
for i in range(30):
    ans += Str2[l4[i]-1]

print(ans)
```

Flag: `BUCKEYE{M4TH–CLA55–W4S–B0R1NG}`

### Buttons

In this challenge we are given a `.jar` file.

We can run the file using the following command:

```
java -jar Buttons.jar
```

When we run the file, we see a GUI program with lots of buttons on the
screen. Apparently, we need to click the buttons in a particular order to
get the flag.

We can see the underlying logic by using any Java decompiler. Going through
the code, it was observed that the order in which we click the buttons is
used to decrypt the flag. The correct order is stored in a two dimensional
array which resembles the grid of buttons that we see in the GUI.

The way I solved the challenge was by labelling the buttons in the GUI.
Another way to solve this would be to write a script that translates the
two dimensional array into a moves history.

This is the line we change to reveal the buttons to be clicked in the GUI:

```
this.buttons[b][b1] = new JButton(Integer.toString(this.grid[b][b1]));
```

Now we can compile the deompiled program and run it:

```
$ javac Buttons.java
$ java Buttons
```

Now we can manually click all the buttons with a 1 to get the flag.

Flag: `buckeye{am4z1ng_j0b_y0u_b1g_j4va_h4ck3r}`

### Headless Horseman

This is an interesting challenge in which we are given split up binaries in
various architectures. The first file is easy to reverse to get the number
which answers the question. After we reverse it, we see that the program
requires us to input `0xFACEDEAD` and when we enter that, we get a bunch of
new files dumped on us ending with the suffix `_head`.

On inspecting the files, it seemed that we needed to concatenating files in
the body bag with the files in the head bag. I wrote a Python file to
stitch up all combinations of heads and bodies:

```
heads = ["dessicated", "fetid", "moldy", "putrid", "shrunken", "swollen"]
bodies = ["bloated", "decomposing", "rotting"]

for head in heads:
    for body in bodies:
        infile_paths = [head + '_head', body + '_body']
        outfile_path = head + '_' + body

        with open(outfile_path, 'wb') as outfile:
            for infile_path in infile_paths:
                with open(infile_path, 'rb') as infile:
                    outfile.write(infile.read())
```

We can put all these files in a single folder and then run:

```
file *
```

This will help us easily discern which files are valid binaries. Since the
binaries are not necessarily x86, I reverse engineered them statically and
was able to get the flag.

One of the binaries required an answer that was given in the project
description:

```
What should Katrina use as the decryption key? Sleepy Hollow
```

Most other files are easy to reverse.

Flag: `flag{the_horseman_just_really_loves_pumpkin_pie}`

## pwn
### Staff

I wasn't able to solve this challenge during the CTF, but it was an
interesting solution so I am mentioning it here.

In the challenge, we didn't exploit any overflow. We simply had two
functions that had two local variables.

```
static void find_instructor(struct Course *courses, int course_count) {
    char instructor[0x20];
    char course[0x20];
    -snip-
}

static void find_course(struct Course *courses, int course_count) {
    char course[0x20];
    char instructor[0x20];
    -snip-
}
```

If we call the `find_course` function first, it fills up both the
variables. Then if we call `find_instructor` the offset of `course` matches
the offset of `instructor` in the previously called function. This variable
is printed in the end.

Looking at the given text file, we need to first find course `FLAG 1337`
and the find instructor `Staff` which should give us our flag.

## ret4win

I was not able to solve this challenge during the CTF. But I found this
challenge interesting so I am going to write it up here.

The challenge code looks like this:

```
void win(int arg0, int arg1, int arg2, int arg3, int arg4, int arg5) {
    char* cmd = "cat flag.txt";
    if (arg0 == 0xdeadbeef && arg1 == 0xcafebabe && arg2 == 0xbeeeeeef &&
        arg3 == 0x13333337 && arg4 == 0x12345678 && arg5 == 0xabcdefed) {
        system(cmd);
    }
}

void vuln() {
    char buf[32];
    puts("Please leave a message at the tone: **beep**");
    read(0, buf, 32 + 8 + 16);
    close(0);
}

int main() {
    vuln();
    return 0;
}
```

So we can go to the `win` function. However we also need to satisfy all
those arguments. I first thought we could do this by finding ROP gadgets
that move stuff into the registers corresponding to those arguments. But I
couldn't find enough of those gadgets to solve it that way. That was when I
gave up.

After the CTF ended, I looked at the solution and it was so simple. We
first jump to the `win` function through the overflow. The second jump we
make is exactly where the `system(cmd)` is located _within_ the `win`
function. Since `cmd` is already filled through the previous run, it should
now cat the flag.
