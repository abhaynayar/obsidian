## Reverse Engineering for Beginners
https://beginners.re

### Chapter 1 - Code Patterns

- Try to see the relationship between C/C++ and assembly by compiling small snippets.
- You don't need to install a compiler on your machine, just use: https://godbolt.org
- You can also start writing in assembly and reducing unnecessary instructions.

Each CPU has a fixed set of GPR:

- 8 in x86
- 16 in x86-64
- 16 in ARM

CISC vs RISC:

- The x86 ISA has always had variable-length instructions the x64 extensions did not impact the ISA very significantly.
- In the very beginning, all ARM instructions were encoded in 4 bytes 5. This is now referred to as "ARM mode".
- They therefore added another ISA, called Thumb, in which each instruction was encoded in just 2 bytes.
- Thumb-2, which appeared in ARMv7 still uses 2-byte instructions, but has some new instructions which have the size of 4 bytes.
- Now having three ARM instruction sets: ARM mode, Thumb mode (including Thumb-2) and ARM64.

Divisibility

- When you see a decimal number like 120, you can quickly deduce that it’s divisible by 10, because the last digit is zero.
- In the same way, 123400 is divisible by 100, because the two last digits are zeros.
- Likewise, the hexadecimal number 0x1230 is divisible by 0x10, binary number 0b1000101000 is divisible by 0b1000.
- This property can often be used to quickly realize if an address or a size of some block in memory is padded to some boundary.
- For example all PE sections are padded to a boundary of 0x1000 (4096) bytes.

#### An empty function

Source

```
void foo() {
    return;
}
```

x86-64

```
push    rbp
mov     rbp, rsp
nop
pop     rbp
ret
```

ARMv7

```
bx      lr
```

#### Returning integers

Source

```
int foo() {
    return 42;
}
```

x86-64

```
push    rbp
mov     rbp, rsp
mov     eax, 42
pop     rbp
ret
```

ARMv7

```
movw    r0, #42
bx      lr
```


#### Printing values

Source

```
#include <stdio.h>
int main() {
    printf("hello, world\n");
    return 0;
}
```

x86-64

```
.LC0:
        .string "hello, world"
main:
        push    rbp
        mov     rbp, rsp
        mov     edi, OFFSET FLAT:.LC0
        call    puts
        mov     eax, 0
        pop     rbp
        ret
```

- The `printf` has been optimized to `puts`
- In Win64, 4 function arguments are passed in the RCX, RDX, R8, and R9 registers and in Linux: RDI, RSI, RDX, RCX, R8, R9 and the rest via stack.
- Sometimes the function prologue has `AND ESP, 0FFFFFFF0h` as the CPU performs better if the values it is dealing with are located in memory at addresses aligned on a 4-byte or 16-byte boundary).
- When you see `SUB ESP, 10h` it allocates 16 bytes on the stack even if required bytes are only 4. This is because the stack is aligned.
- LEAVE is the equivalent of the `MOV ESP, EBP` and `POP EBP` instruction pair.
- The number of used vector registers is to be passed in EAX in *NIX systems on x86-64 before a function call.

#### Some differences in AT&T syntax

- Source and destination operands are swapped.
- Percent sign before register names, and dollars before numbers.
- Parenthesis () are used instead of brackets [].
- Suffix is added to define operand size: qlwb.


ARMv7

```
```

