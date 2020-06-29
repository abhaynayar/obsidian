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

Q1. What does this code do? What is the type of the [EBP+8] and [EBP+C] in line 1 and 8?

```
mov edi, [ebp+8]    ; edi = [ebp+8] (address of a str)
mov edx, edi        ; edx = edi (duplicate address)
xor eax, eax        ; eax = 0 (null-byte)
or ecx, 0FFFFFFFFh  ; ecx = -1 (no. of repititions)
repne scasb         ; while(edi!=null && ecx!=0) { edi++; ecx--; }
add ecx, 2          ; ecx+=2 (starting at -1 and null byte)
neg ecx             ; ecx = -ecx (length of string is positive)
mov al, [ebp+0Ch]   ; al = [ebp+0Ch] (value of a chr)
mov edi, edx        ; edi = edx (back to original str)
rep stosb           ; while(ecx!=0) { edi=al; ecx-- }
mov eax, edx        ; eax = edx
```

Arithmetic Operations

- When multiplying or dividing by two, we use shift operations (this is called _strength reduction_).
- MUL/IMUL is used for unsigned/signed multiplication. It has three forms: 

```
IMUL reg/mem — Same as MUL (stored in AX, DX:AX, EDX:EAX)
IMUL reg1, reg2/mem — reg1 = reg1 * reg2/mem
IMUL reg1, reg2/mem, imm — reg1 = reg2 * imm
```

- Similarly we have DIV/IDIV for unsigned/signed division, they only take one parameter as the divisor and use AX, DX:AX, or EDX:EAX as the dividend. The resulting quotient/remainder is stored in AL/AH, AX/DX, or EAX/EDX.

Stack operations and function invocation


