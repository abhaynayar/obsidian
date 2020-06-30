## Practical Reverse Engineering
### x86 and x64

- It is a little-endian architecture based on the Intel 8086 processor.
- Supports the concept of privilege separation through an abstraction called ring level.
- User-mode applications run in ring 3, and the kernel in ring 0.
- The ring level is encoded in the CS register and called CPL.

General Purpose Registers:

- ECX: Counter in loops
- ESI: Source in string/memory operations
- EDI: Destination in string/memory operations
- EBP: Base frame pointer
- ESP: Stack pointer

Data-types:

- Bytes — 8 bits: AL, BL, CL
- Word — 16 bits: AX, BX, CX
- Double word — 32 bits: EAX, EBX, ECX
- Quad word — 64 bits: EDX and EAX

Instruction set:

- Immediate to register
- Register to register
- Immediate to memory
- Register to memory and vice versa
- Memory to memory (only x86)

Moving data:

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

Exercise:

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

Arithmetic Operations:

When multiplying or dividing by two, we use shift operations (this is called _strength reduction_). MUL/IMUL is used for unsigned/signed multiplication. It has three forms: 

```
IMUL reg/mem — Same as MUL (stored in AX, DX:AX, EDX:EAX)
IMUL reg1, reg2/mem — reg1 = reg1 * reg2/mem
IMUL reg1, reg2/mem, imm — reg1 = reg2 * imm
```

Similarly we have DIV/IDIV for unsigned/signed division, they only take one parameter as the divisor and use AX, DX:AX, or EDX:EAX as the dividend. The resulting quotient/remainder is stored in AL/AH, AX/DX, or EAX/EDX.

Stack operations and function invocation ⭐

- Local variables in C are stored on the functions’ stack space.
- The stack is mainly used on a function scale, we don't individually push or pop integers to the stack. The ESP and EBP are governed by functions.
- When the operating system transitions from ring 3 to ring 0, it saves state information on the stack.
- PUSH decrements ESP and then writes data at the location pointed to by ESP while POP reads the data and increments esp.
- The default auto-increment/decrement value is 4, but it can be changed to 1 or 2 with a prefix override. In practice, the value is almost always 4 because the OS requires the stack to be double-word aligned.
- A _calling convention_ is a set of rules dictating how function calls work at the machine level. It is defined by the Application Binary Interface (ABI) for a particular system.
- Popular calling conventions include: CDECL, STDCALL, THISCALL, and FASTCALL.
- CALL performs two operations: pushes return value to stack, jumps to EIP.
- After call, we have the function prologue: `push ebp; mov ebp, esp`
- EBP is used to access function parameters and local variables.
- All local variables are accessible through a negative offset from EBP.
- Frame pointer omission: access to local variables and parameters is done relative to ESP, and EBP can be used as a general register.
- At the end we have function epilogue: `mov esp, ebp; pop ebp; retn`
- RET pops the address stored on top of the stack, and jumps to it.
- CALL is same as JUMP except it pushes EIP on to the stack.
- During a CALL in 64-bit binaries, the RSP decrements by two addresses, i.e., it decrements by four bytes twice since 4-bytes \* 2 = 8-bytes = 64-bits.

Exercises:

Q1. EIP can't be read using MOV but we can use CALL to put it on top of the stack and then read ESP.

Q2. EIP can be modified using RET, JMP and CALL.

Q3. What happens if ESP is not restored before RET in the following code?

```
push eax
push ecx
call addme ; push ret,  jmp addme
add esp, 8 ; pop ret, pop ebp
```

Disassembly of addme:

```
push ebp
mov ebp, esp
movsx eax, word ptr [ebp+8]
movsx ecx, word ptr [ebp+0Ch]
add eax, ecx ; result stored in eax
mov esp, ebp ; esp is still ebp since nothing has been pushed onto the stack, therefore this instruction can be ignored
pop ebp
retn
```


