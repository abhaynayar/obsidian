## 

### hoth 200 pts.

We are given a PE32 binary, but since we had to use the university computers (which had Ubuntu 16.04) I could only do a static analysis. Below is a snippet of the main function, after getting the user input the program calls \_check function.

```
0x0040142d      call sym._scanf            
0x00401432      lea eax, dword [local_18h] 
0x00401436      mov dword [esp], eax
0x00401439      call sym._check
```

In the \_check function there are a lot of mov instructions in the beginning.

```
0x0040147d      c785b4feffff.  mov dword [local_14ch], 0x7b ; '{' ; 123
0x00401487      c785b8feffff.  mov dword [local_148h], 0x48 ; 'H' ; 72
0x00401491      c785bcfeffff.  mov dword [local_144h], 0x75 ; 'u' ; 117
0x0040149b      c785c0feffff.  mov dword [local_140h], 0x83 ; 131
0x004014a5      c785c4feffff.  mov dword [local_13ch], 0x70 ; 'p' ; 112
0x004014af      c785c8feffff.  mov dword [local_138h], 0x75 ; 'u' ; 117
```

Also there are a few operations being performed on the individuals bytes, before being compared to our input.

```
0x00401602      83e806         sub eax, 6
0x00401605      83f01e         xor eax, 0x1e
0x00401608      83c005         add eax, 5
```

So in order to reverse the operations, we need to subtract 5, xor 0x1e and add 6. So I extracted all the bytes that were being moved in the begin of the \_check function and wrote this small python script to get the flag.

```
a = "\x82\x7B\x48\x75\x83\x70\x75\x81\x82\x78\x4C\x82\x78\x4C\x78\x82\x7E\x79\x7D\x46\x77\x4C\x75\x81\x4A\x7B\x4C\x72\x7C\x76\x4C\x75\x81\    x82\x7B\x80\x6E"

for i in a:
     print(chr((ord(i)-5^0x1e)+6),end='')
```

```
inctf{this_is_simpler_than_you_think}
```

