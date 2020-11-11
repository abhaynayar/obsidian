## Hack The Vote 2020
### x96

In this challenge, we are given a 32-bit ELF called [x96](x96).  

After disassembling it in IDA, we get the following code at the entry
point.

```asm
LOAD:08048054 start           proc far
LOAD:08048054                 dec     eax
LOAD:08048055                 mov     ax, cs
LOAD:08048058                 cmp     ax, 23h
LOAD:0804805C                 jnz     loc_80481A5
LOAD:08048062                 push    eax
LOAD:08048063                 or      al, 13h
LOAD:08048065                 push    eax
LOAD:08048066                 push    offset dword_804806C
LOAD:0804806B                 retf
```

The `retf` instruction at the end pops the IP followed by the CS register. 
Looking at the preceding instructions, we can see that the value of CS
register becomes `0x33` and that of IP becomes `0x804806c` which is
actually the next instruction in the code.

However, IDA fails to identify it as code. After doing some research I
came across the fact that when CS is set to `0x33` the instructions are
interpreted as 64-bit. You can read more about it [here](http://scrammed.blogspot.com/2014/10/code-obfunscation-mixing-32-and-64-bit.html). Another
interesting artefact of interpreting the code as 64-bit with IDA thinking
it as 32-bit, is that we see a lot of `dec eax` instructions.
Coincidentally I remembered a [tweet](https://twitter.com/struppigel/status/1208027470399713280) related to this that I had stored in my bookmarks.

So, in order to understand the code, we need IDA to interpret it as 64-bit.
We can do this by selecting the area that we want to generate code for
(in the text-view) then going to Edit > Segment > Create Segment. In the
dialog box that follows, make sure to select 64-bit segment. Once we have
repurposed that area we can go to Edit > Code to generate the 64-bit code
for that segment.

```asm
64seg:000000000804806C loc_804806C:
64seg:000000000804806C                 mov     rax, 0DF3A0F66090F1B37h
64seg:0000000008048076                 mov     rdi, 0E9F4E2EBE86423CAh
64seg:0000000008048080                 xor     eax, eax
64seg:0000000008048082                 xor     rdi, rdi
64seg:0000000008048085                 mov     rsi, 80481F6h
64seg:000000000804808C                 mov     rdx, 24h
64seg:0000000008048093                 syscall ; LINUX - sys_read
64seg:0000000008048095                 mov     rdx, offset sub_8048175
64seg:000000000804809C                 mov     ecx, 0
64seg:00000000080480A1
64seg:00000000080480A1 loc_80480A1:
64seg:00000000080480A1                 mov     rbx, 358D0150819CF3C4h
64seg:00000000080480AB                 ror     rbx, cl
64seg:00000000080480AE                 cmp     ecx, 24h
64seg:00000000080480B1                 jz      loc_8048154
64seg:00000000080480B7                 mov     al, [ecx+80481F6h]
64seg:00000000080480BE                 xor     al, bl
64seg:00000000080480C0                 mov     r15, 0B8E8AE0F00000000h
64seg:00000000080480CA                 cmp     al, ds:byte_80481C3[ecx]
64seg:00000000080480D1                 jz      short loc_8048115
64seg:00000000080480D3                 push    0
64seg:00000000080480D5                 mov     rax, 2300000000h
64seg:00000000080480DF                 shr     rax, 18h
64seg:00000000080480E3                 mov     dword ptr [rsp+4], 0
64seg:00000000080480EB                 mov     [rsp+7], ah
64seg:00000000080480EF                 mov     dword ptr [rsp], offset unk_80480F8
64seg:00000000080480F6                 retfq
```

Beyond this, we get another string of data which IDA didn't recognize as
code. However, this time it is 32-bit code. So we can simply hit Edit >
Code to get the intended code.

```asm
_32seg:080480F8 loc_80480F8:
_32seg:080480F8                 dec     eax
_32seg:080480F9                 mov     eax, 0
_32seg:080480FE                 mov     edx, offset loc_80481A5
_32seg:08048103                 inc     ecx
_32seg:08048104                 dec     eax
_32seg:08048105                 mov     eax, 23h
_32seg:0804810A                 push    eax
_32seg:0804810B                 dec     eax
_32seg:0804810C                 or      al, 13h
_32seg:0804810E                 push    eax
_32seg:0804810F                 push    offset loc_80480A1
_32seg:08048114                 retf
_32seg:08048114 _32seg          ends
```

After we have the "right" code, the program is trivially easy to crack. It
checks the user input against the XOR of a set of values in the data
section (at address `080481C3`) with a rotating value in a register (all
of this is included in the code above).

Here I have written a python script to get the flag:

```python
rbx = 0x358D0150819CF3C4

data = [0xa2, 0x8e, 0x90, 0x1f, 0x47, 0xf0, 0xfc, 0x9f, 0x87, 0x26, \
        0x48, 0xaf, 0xa2, 0xd4, 0x2c, 0x4e, 0xaf, 0x91, 0x0d, 0x46, \
        0x74, 0x7c, 0x59, 0x77, 0xb1, 0x1f, 0x52, 0x23, 0x3c, 0xe8, \
        0x1d, 0xcc, 0x60, 0xcc, 0x67, 0x57]

def ror(n,d):
    return (n>>d)|(n<<(64-d)) & 0xFFFFFFFFFFFFFFFF

flag = ''
for i in range(0x24):
    flag += chr(data[i] ^ (ror(rbx,i)&0xff))

print(flag)
```

Flag: `flag{n3xt_t1m3_w3_jump_t0_r34l_m0d3}`

