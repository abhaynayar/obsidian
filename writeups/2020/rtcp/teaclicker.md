## riceteacatpanda 2020
### Tea Clicker

When you run the binary, you get a window on which there is a tea cup and
a score, you have to click the tea-cup to increment the score and after
999999999999 clicks, you get the flag. At first I thought it was doable
using an automated clicker but after using one for the first time and
realizing how slow it is, it was apparent that was not the intended
solution.

```
#!/bin/bash
while [ 1 ]; do
  xdotool mousemove XXX YYY click 1 &
done
```

Then I got to know about the Cheat Engine. I had already heard about it,
but thanks to some hints in the Discord server, I used Cheat Engine, but
to no avail. It took me a while to figure out that the value type that I
was suposed to search for was a double, while I was only checking for a
4-byte integer.

![](ce.png)

After that it was just the task of modifying the variable to get the flag.

Flag: `rtcp{w0w_ur_5uch_a_t2^_g^m3r}`
