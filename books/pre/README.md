## Practical Reverse Engineering
### x86 and x64

x86

- It is a little-endian architecture based on the Intel 8086 processor.
- Supports the concept of privilege separation through an abstraction called ring level.
- User-mode applications run in ring 3, and the kernel in ring 0.
- The ring level is encoded in the CS register and called CPL.

Registers

- ECX Counter in loops
- ESI Source in string/memory operations
- EDI Destination in string/memory operations
- EBP Base frame pointer
- ESP Stack pointer

Data-types

- Bytes — 8 bits: AL, BL, CL
- Word — 16 bits: AX, BX, CX
- Double word — 32 bits: EAX, EBX, ECX
- Quad word — 64 bits: EDX and EAX

Instruction set

- Immediate to register
- Register to register
- Immediate to memory
- Register to memory and vice versa
- Memory to memory (only x86)

Moving data

- MOVSB/MOVSW/MOVSD instructions move data with 1-, 2-, or 4-byte granularity between two memory addresses.
- They implicitly use EDI/ESI as the destination/source address, respectively using direction flag.
- Although the LEA instruction uses [], it actually does not read from a memory address.
- REP prefix repeats an instruction up to ECX times.
- STOS writes the value AL/AX/EAX to EDI depending on the direction flag.
- LODS reads a 1-, 2-, or 4-byte value from ESI and stores it in AL, AX, or EAX.
- SCAS implicitly compares AL/AX/EAX with data starting at the memory address EDI.

```
xor al, al
mov ebx, edi
repne scasb
sub edi, ebx
```

Exercise

What does this code do?

```
mov edi, [ebp+8]    ; edi = value at [ebp+8]
mov edx, edi        ; edx = edi
or ecx, 0FFFFFFFFh  ; ecx = 0FFFFFFFFh
repne scasb         ; while(al!=edi) edi++
add ecx, 2          ; ecx += 2 => ecx = 1
neg ecx             ; ecx = -ecx => ecx = 0FFFFFFFFh
mov al, [ebp+0Ch]   ; al = value at [ebp+0Ch]
mov edi, edx        ; edi = edx
rep stosb           ; while(al!=edi) edi=al
mov eax, edx        ; eax = edx
```




