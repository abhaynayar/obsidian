## Practical Reverse Engineering
### x86 and x64

x86:

- It is a little-endian architecture based on the Intel 8086 processor
  released in 1978.
- Supports the concept of privilege separation through an abstraction
  called ring level.
- User-mode applications run in ring 3, and the kernel in ring 0.
- The ring level is encoded in the CS register and called CPL.
- Real mode is the processor state when it is first powered on and only
  supports a 16-bit instruction set.
- Protected mode is the processor state supporting virtual memory, paging,
  and other features; it is the state in which modern operating systems
  execute.
- Most operating systems on the x86/x64 platform run in protected mode and
  rarely, if ever, switch back to real mode.

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

- MOVSB/MOVSW/MOVSD instructions move data with 1-, 2-, or 4-byte
  granularity between two memory addresses.
- They implicitly use EDI/ESI as the destination/source address,
  respectively using direction flag.
- Although the LEA instruction uses [], it actually does not read from a
  memory address.
- REP prefix repeats an instruction up to ECX times.
- STOS writes the value AL/AX/EAX to EDI depending on the direction flag.
- LODS reads a 1-, 2-, or 4-byte value from ESI and stores it in AL, AX, or
  EAX.
- SCAS implicitly compares AL/AX/EAX with data starting at the memory
  address EDI.

```
xor al, al
mov ebx, edi
repne scasb
sub edi, ebx
```

Exercise

Q1. What does this code do? What is the type of the [EBP+8] and [EBP+C] in
line 1 and 8?

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

When multiplying or dividing by two, we use shift operations (this is
called _strength reduction_). MUL/IMUL is used for unsigned/signed
multiplication. It has three forms: 

```
IMUL reg/mem — Same as MUL (stored in AX, DX:AX, EDX:EAX)
IMUL reg1, reg2/mem — reg1 = reg1 * reg2/mem
IMUL reg1, reg2/mem, imm — reg1 = reg2 * imm
```

Similarly we have DIV/IDIV for unsigned/signed division, they only take one
parameter as the divisor and use AX, DX:AX, or EDX:EAX as the dividend. The
resulting quotient/remainder is stored in AL/AH, AX/DX, or EAX/EDX.

Stack operations and function invocation ⭐

- Local variables in C are stored on the functions’ stack space.
- The stack is mainly used on a function scale, we don't individually push
  or pop integers to the stack. The ESP and EBP are governed by functions.
- When the operating system transitions from ring 3 to ring 0, it saves
  state information on the stack.
- PUSH decrements ESP and then writes data at the location pointed to by
  ESP while POP reads the data and increments esp.
- The default auto-increment/decrement value is 4, but it can be changed to
  1 or 2 with a prefix override. In practice, the value is almost always 4
  because the OS requires the stack to be double-word aligned.
- A _calling convention_ is a set of rules dictating how function calls
  work at the machine level. It is defined by the Application Binary
  Interface (ABI) for a particular system.
- Popular calling conventions include: CDECL, STDCALL, THISCALL, and
  FASTCALL.
- CALL performs two operations: pushes return value to stack, jumps to EIP.
- After call, we have the function prologue: `push ebp; mov ebp, esp`
- EBP is used to access function parameters and local variables.
- All local variables are accessible through a negative offset from EBP.
- Frame pointer omission: access to local variables and parameters is done
  relative to ESP, and EBP can be used as a general register.
- At the end we have function epilogue: `mov esp, ebp; pop ebp; retn`
- RET pops the address stored on top of the stack, and jumps to it.
- CALL is same as JUMP except it pushes EIP on to the stack.
- During a CALL in 64-bit binaries, the RSP decrements by two addresses,
  i.e., it decrements by four bytes twice since `4 bytes * 2 = 8 bytes = 64
  bits`

Exercises:

Q1. EIP can't be directly modified because there is no legitimate use case
[1](https://stackoverflow.com/questions/8333413/why-cant-you-set-the-instruction-pointer-directly)
but we can use CALL to put it on top of the stack and then read ESP.

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

Q4. What happens if the return value of a function can't fit in EAX?

A4. It overflows into EDX and when stored in memory, they are adjacent in
accordance with little-endian.

Control Flow:

- ZF: set if the result of the previous arithmetic operation is zero.
- SF: the most significant bit of the result.
- CF: set if the result requires a carry (unsigned numbers).
- OF: set if the result overflows the max size (signed numbers).

Conditional codes:

- In total there are 16, but here are some common ones.
- Greater/less is used for signed while above/below is used for unsigned
  comparison.

| Opcode | Condition     |
|--------|---------------|
| B/NAE  | CF=1          |
| NB/AE  | CF=0          |
| E/Z    | ZF=1          |
| NE/NZ  | ZF=0          |
| L      | SF^OF=1       |
| GE/NL  | SF^OF=0       |
| G/NLE  | (SF^OF)\|ZF=0 |

- If/else statements are simply a compare followed by a jump.
- Switch case may be a sequence of if/else statements or a _jump table_.
- Jump table is an array of addresses pointing to specific cases.
- Loops are implemented using comparison and jumps cleverly.

System Mechanism

Virtual address translation

- The physical memory on a computer system is divided into 4KB units called
  pages.
- The processor’s memory management unit (MMU) transparently translates
  every virtual address into a physical address before accessing it.
- Virtual addresses in x86 systems with physical address extension (PAE)
  support.
- page directory pointer table (PDPT) -> page directory (PD) -> page table
  (PT) -> page table entry (PTE)
- 2 bits + 9 bits + 9 bits + 12 bits = 32 bits (these are all 8 byte
  elements)
- Every process has a CR3 register that holds the physical base address of
  a PDPT.

```
virtual address = 0xBF80EE6B
1011 1111 1000 0000 1110 1110 0110 1011
  10 111111100 000001110 111001101011
 0x2     0x1fc       0xe        0xe6b

cr3  = 00000000 085c01e0 => 0x085c01e0 + 0x02
pdpt = 00000000 0d66e001 => 0x0d66e000 + 0x1fc
pd   = 00000000 0964b063 => 0x0964b000 + 0x0e
pt   = 00000000 06694021 => 0x06694000 + 0xe6b

physical address = 0x6694E6B
```

Exception / interrupt handling:

- When a device requires the processor’s attention, it causes an interrupt
  that forces the processor to pause whatever it is doing and handle the
  device’s request. These are called hardware interrupts because they are
  generated by hardware devices. They are asynchronous by nature.
- Exceptions can be classified into two categories: faults and traps. A
  fault is a correctable exception (eg. page fault). A trap is an exception
  caused by executing special kinds of instructions (eg. SYSENTER).

**An important requirement in the practice of reverse engineering: reading
technical manuals and online documentation.**

Walkthrough:

```
TBD
```

x64:

- x64 supports a concept referred to as RIP-relative addressing.
- x64 also needs to use canonical addresses.

Canonical Address:

- Virtual addresses in x64 are 64 bits in width, but most processors do not
  support a full 64-bit virtual address space.
- Current Intel/AMD processors only use 48 bits for the address space so
  they need to use canonical addresses.
- An address is canonical if bits 48–63 match bit 47. An exception will be
  caused if a non-canonical address is derefenced.

Calling conventions:

- On Windows x64, there is only one calling convention: the first four
  parameters are passed through RCX, RDX, R8, and R9; while the remaining
  are pushed on the stack from right to left
  (https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions).
- On Linux, the first six parameters are passed on RDI, RSI, RDX, RCX, R8,
  and R9.

### ARM

ARM families and architectures
([source](https://en.wikipedia.org/wiki/List_of_ARM_microarchitectures#ARM_cores)):

| ARM family  | ARM architecture |
|-------------|------------------|
| ARM7 	      | ARM v4           |
| ARM9 	      | ARM v5           |
| ARM11 	  | ARM v6           |
| Cortex-A 	  | ARM v7-A         |
| Cortex-R 	  | ARM v7-R         |
| Cortex-M 	  | ARM v7-M         |

History:

- The Wikipedia [article](https://en.wikipedia.org/wiki/ARM_architecture)
  on arm seems interesting.
- Arm, previously Advanced RISC Machine, originally Acorn RISC Machine.
- Keil is a German software subsidiary of ARM.
- The first version of the architecture was introduced in 1985, starting
  from ARMv1 to the latest ARMv8-a.
- While Intel and AMD manufacture their own processors, ARM licenses these
  designs to a number of companies.

| Company           | Processor  |
|-------------------|------------|
| Apple             | A          |
| NVIDIA            | Tegra      |
| Qualcomm          | Snapdragon |
| Texas Instruments | OMAP       |

- Additional extensions can be added to the processor which can also be
  licensed by third party companies.
- Till ARMv6 these extensions appear as letters (J,T,D given in table
  below) at the end of the processor names.
- Starting from [ARMv7](https://www.arm.com/products/silicon-ip-cpu) we
  have three profiles (Application, real-time and microcontroller) along
  with model names (Cortex).
  - Cortex-A series are processors with the application profile.
  - Cortex-M are meant for microcontrollers and only support Thumb mode
    execution.

| Extension | Description                                                                                |
|-----------|--------------------------------------------------------------------------------------------|
| Jazelle   | Enables Java bytecode to be run natively on the processor                                  |
| Thumb     | 16 or 32 bit for higher code density (native ARM instructions are always 32 bits in width) |
| Debug     | Allows us to analyze the physical processor using special debugging hardware               |

Instruction set:

- [ARMv7 manual](https://static.docs.arm.com/ddi0406/c/DDI0406C_C_arm_architecture_reference_manual.pdf)
- Instruction set is very small compared to x86 but offers more
  general-purpose registers.
- Instruction length is fixed width (16 or 32 bits, depending on the
  state).
- Uses a load-store model for memory access (unlike x86, it can't change
  memory contents directly).
- Barrel shifter: certain instructions can contain other shift or rotate
  instructions `MOV R1, R0, LSL #1 ; R1 = R0 * 2`

Privelege modes:

- In ARM we have 8 different privelege modes (unlike in x86 where we have
  four rings):
  - User (USR) - user mode
  - Fast interrupt request (FIQ)
  - Interrupt request (IRQ)
  - Supervisor (SVC) - kernel mode
  - Monitor (MON)
  - Abort (ABT)
  - Undefined (UND)
  - System (SYS)
- Code running in SVC mode can be either ARM or Thumb.
- In ARM state, instructions are always 32 bits wide.
- In thumb state, instructions can be either 16 bits or 32 bits wide.
- When an ARM core boots up, most of the time it enters ARM state.
- And remains that way until there is an explicit or implicit change to
  Thumb:
    - If after a BX or BLX, the destination register's LSB is 1.
    - If the T bit in the CSPR register is set.

Thumb state:

- In practice, recent OS codes mainly use Thumb code for high code density.
- Applications can operate in whatever mode they want.
- 32-bit Thumb instructions have a `.W` suffix.
- There are two versions of Thumb: Thumb-1 and Thumb-2.
- Thumb-1 was used in ARMv6 and earlier architectures, and its instructions
  are always 16 bits in width.
- Thumb-2 extends that by adding more instructions and allowing them to be
  either 16 or 32 bits in width.
- ARMv7 requires Thumb-2.

Conditional execution:

- Supports conditional execution: an instruction encodes certain arithmetic
  conditions that must be met in order for it to be executed.
- Unlike x86, for which almost every single instruction is executed
  unconditionally.
- Conditional execution is important as it it cuts down on branch
  instructions (they are expensive and lead to higher code density).
- All instructions in ARM state support conditional execution, but by
  default they execute unconditionally.
- In Thumb state, a special instruction IT is required to enable
  conditional execution.

Data types and registers:

- Supported data types are: 8-bit (byte), 16-bit (half-word), 32-bit
  (word), and 64-bit (double-word).
- There are sixteen 32-bit general-purpose registers, numbered R0, R1, R2,
  ..., R15.
- R13 / stack pointer (SP): points to the top of the program stack.
- R14 / link register (LR): holds the return address during a function
  call.
- R15 / program counter (PC): holds address 2 instructions ahead of the
  current instruction {+8 in ARM state | +4 in Thumb state}
- But when debugging, PC points to the instruction that is to be executed.
  (due to legacy pipelining)
- A major difference from EIP is that code can directly read from and write
  to the PC register.

Current program status register (CPSR):

| Bits  | Function        |
|-------|-----------------|
| 0-3   | Privilege mode  |
| 4     | Thumb state     |
| 5-8   | -               |
| 9     | Big endian      |
| 10-14 | IT (?)          |
| 26-30 | Condition flags |

System-level control and settings:

- There are 16 coprocessors in the ARM architecture: CP0, CP1, ..., CP15
  (when used in code, these are referred to as P0, ..., P15).
- CP10 and CP11 are usually used for fl oating-point and NEON support.
- NEON provides the single-instruction multiple data (SIMD) instruction set
  that is commonly used in multimedia applications. It is similar to
  SSE/MMX instructions in x86-based architectures.
- CP14 and CP15 are used for debug and system settings.
- CP15, usually known as the system control coprocessor, stores most of the
  system settings (caching, paging, exceptions, and so forth).
- Accessing coprocessors can only be done through the MRC (read) and MCR
  (write) instructions.
- Some of the coprocessor registers and opcodes are only accessible in SVC
  mode.

```
; read coprocessor 15’s C2/C0 register using opcode 0/0 and store the result in the general-purpose register R0
MRC p15, 0, r0, c2, c0, 0 ; save translation base register (TTBR) in r0
```

Instruction set:

Running your assembly code ([source](https://azeria-labs.com/writing-arm-assembly-part-1/))

- First you need to have an ARM based processor (maybe Raspberry Pi on
  QEMU)
- Then after writing your program and saving it as `program.s`

```
$ as program.s -o program.o
$ ld program.o -o program
```

- On ARM, the load/store instructions are LDR/STR, LDM/STM, and PUSH/POP.
- For STM, some disassemblers will show STMEA if the base register is SP,
  and STMIA for other registers; some always use STM; and some always use
  STMIA.

```
STM R1, {R6-R10}  ; store R6-R10 at the address specified by R1 (R6 at R1, R7 at R1+4 and so on)
STM R2, {R3,R4}   ; non-consecutive registers can also be stored
STM R1!, {R6-R10} ; store as before, and update R1 to address after R10
```

Simple case:

```
LDR R3, [R0] ; R3 = *R0
STR R3, [R4] ; *R4 = R3;
```

Offset: immediate, register and scaled register

```
STR Ra, [Rb, imm]
LDR Ra, [Rc, imm]
```

```
STR Ra, [Rb, Rc]
LDR Ra, [Rb, Rc]
```

```
LDR Ra, [Rb, Rc, <shifter>]
STR Ra, [Rb, Rc, <shifter>]
LDR.W R2, [R0,R3,LSL#2] ; example
```
