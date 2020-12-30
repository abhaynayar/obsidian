## Reverse Engineering for Beginners
https://beginners.re

Important points

- You don't need to install a compiler on your machine, just use: https://godbolt.org
- You can also start compiling to assembly and reduce unnecessary instructions.
- PE sections are padded to a boundary of 0x1000 (4096) bytes.
- ARM programs use stack to store return addresses since LR will be overwritten (except leaf functions).
- The number of used vector registers is to be passed in EAX in \*NIX systems on x86-64 before a function call: https://stackoverflow.com/questions/6212665/why-is-eax-zeroed-before-a-call-to-printf
- All `MOV` instructions in 64-bit mode that write something into the lower 32-bit register part also clear the higher 32-bits. For example `mov eax` has the same effect as `mov rax` however the former may be used since the number of bytes in the opcode are less.
- Use `-static` option in `gcc` to compile a statically linked binary.

ARM instruction sets

- The x86 ISA has always had variable-length instructions, the x64 extensions did not impact the ISA very significantly.
- ARM instructions used to be encoded in 4 bytes. This is now referred to as `ARM mode`.
- Created another ISA, called `Thumb`, in which each instruction was encoded in just 2 bytes.
- `Thumb-2`, which appeared in `ARMv7` still uses 2-byte instructions, but has some new instructions which have the size of 4 bytes.
- Now we have three ARM instruction sets: `ARM` mode, `Thumb` mode (including Thumb-2) and `ARM64`.

Differences in AT&T syntax

- Source and destination operands are swapped.
- Percent sign before register names, and dollars before numbers.
- Parenthesis `()` are used instead of brackets `[]`.
- Suffix is added to define operand size: `qlwb`.

Calling conventions

- The most popular way is `cdecl` in which callee functions get their arguments via the stack pointer.

Fastcall (passing function arguments through registers)

- Win64: `RCX, RDX, R8, R9`
- Linux: `RDI, RSI, RDX, RCX, R8, R9`

Function return value

- x86: `EAX`
- ARM: `r0`

Stack instructions

- `LEAVE`: Equivalent of the `MOV ESP, EBP` and `POP EBP` instruction pair.
- `SUB ESP, 10h`: Allocates 16 bytes on the stack even if required bytes are only 4 (for stack alignment).
- `AND ESP, 0FFFFFFF0h`:
    - CPU performs better if aligned on a 4-byte or 16-byte boundary.
    - This instruction brings the stack pointer to a lower address.
    - Previous stack pointer is already saved on the prologue, so there is no "loss of information".
- Shadow space: `sub rsp, 40`


`STMFD SP!, {R4,LR}`

- Store multiple full descending.
- We can choose to make the stack ascending or descending.
- In this instruction we store the values in `R4` and `LR` on the stack and decrement `SP`
- The exclamation mark after `SP` ensures that the value of SP is modified.
- In Thumb mode, this instruction could be written as `PUSH {r4,lr}`

`STP x29, x30, [sp, -16]!`

- Pushes `x29` and `x30` on to the stack.
