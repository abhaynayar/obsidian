## Reverse Engineering

### Hoth 200 pts.

We are given a PE32 binary, but since we had to use the university computers (which had Ubuntu 16.04) I could only do a static analysis. Below is a snippet of the main function, after getting the user input the program calls \_check function.

```
0x0040142d      call sym._scanf            
0x00401432      lea eax, dword [local_18h] 
0x00401436      mov dword [esp], eax
0x00401439      call sym._check
```

In the \_check function there are a lot of mov instructions in the beginning.

```
0x00401473      c785b0feffff.  mov dword [local_150h], 0x82 ; 130
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
a = "\x82\x7B\x48\x75\x83\x70\x75\x81\x82\x78\x4C\x82\x78\x4C\x78\x82\x7E\x79\x7D\x46\x77\x4C\x75\x81\x4A\x7B\x4C\x72\x7C\x76\x4C\x75\x81\x82\x7B\x80\x6E"

for i in a:
     print(chr((ord(i)-5^0x1e)+6),end='')

# inctf{this_is_simpler_than_you_think}
```

### PartyPart 300 pts.

The program takes our input then does a string compare. If the string is not 42 (0x2a) characters long, it exits.

```
0x0000000000000c9b <+99>:	mov    rdi,rax
0x0000000000000c9e <+102>:	call   0x6d0 <strlen@plt>
0x0000000000000ca3 <+107>:	cmp    rax,0x2a
0x0000000000000ca7 <+111>:	je     0xcbf <main+135>
```

For the rest of the program I used a decompiler. Below is the output after I have cleaned it up for better understanding. Although switch cases are easy to spot even in disassembly, during a CTF, it is always better to ease your burden therefore I took this approach. 

```
puts("Enter Your lucky number!!");
scanf("%d", &num);

for (i=8; i; --i)
{
  switch (num)
  {
    case 0:
      num = first(argv[1][num], num);
      break;
    case 6:
      num = second(argv[1][num], num);
      break;
    case 12:
      num = third(argv[1][num], num);
      break;
    case 18:
      num = fourth(argv[1][num], num);
      break;
    case 24:
      num = fifth(argv[1][num], num);
      break;
    case 30:
      num = sixth(argv[1][num], num);
      break;
    case 36:
      num = seventh(argv[1][num], num);
      break;
    case 42:
      loser();
      return result;
    case 48:
      winner();
      return result;
    default:
      loser();
      return result;
  }
}
```

We are asked to enter a number. Every case calls a function (named using ordinal conventions). The arguments passed are a pointer to a specific position (our number) in input string (which is passed using command line arguments) and our input number. The switch case is especially curious since it is wrapped by a loop that runs eight times so it would seem we would hit the same case again and again.

```
int first (char \*a1, int a2) {
  for (i=0; i<6; ++i)
    temp[i+a2] = a1[i] ^ 8;
  if (strncmp(tem, "afk|ns<ea'pVvj5ar6ginTl&znev:xy~R=kRd7cb&z", a2 + 6))
    return 42;
  return 6;
}
```

The function performs a xor operation on the first six characters of our input string and compares it with the first six characters of ```afk|ns<ea'pVvj5ar6ginTl&znev:xy~R=kRd7cb&z```. Then it returns 42 if the string mismatches else it returns 6. This makes the switch statement clearer. Case 42 calls loses() while case 6 calls second(). Other ordinal functions have similar structure, the only difference being the operation used before comparison. So in total we have seven functions each working on the same string but performing different operations on different chunks (of six characters).

```
a = "afk|ns<ea'pVvj5ar6ginTl&znev:xy~R=kRd7cb&z"
b = []

b += [chr(ord(x)^8) for x in a][0:6]
b += [chr(ord(x)+9) for x in a][6:12]
b += [chr(ord(x)-2) for x in a][12:18]
b += [chr(ord(x)+0xb) for x in a][18:24]
b += [chr(ord(x)-6) for x in a][24:30]
b += [chr(ord(x)^0xd) for x in a][30:36]
b += [chr(ord(x)^7) for x in a][36:42]

print(''.join(b))

# inctf{Enj0y_th3_p4rty_w1th_p4rts_0f_c0de!}
```
