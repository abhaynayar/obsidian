#include <stdio.h>

int main() {
    volatile int a[] = {1,2,3};
    return 0;
}

/*

without volatile:
   0x000000000000114d <+4>:	push   rbp
   0x000000000000114e <+5>:	mov    rbp,rsp
   0x0000000000001151 <+8>:	sub    rsp,0x20
   0x0000000000001155 <+12>:	mov    rax,QWORD PTR fs:0x28
   0x000000000000115e <+21>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001162 <+25>:	xor    eax,eax
   0x0000000000001164 <+27>:	mov    DWORD PTR [rbp-0x14],0x1
   0x000000000000116b <+34>:	mov    DWORD PTR [rbp-0x10],0x2
   0x0000000000001172 <+41>:	mov    DWORD PTR [rbp-0xc],0x3
   0x0000000000001179 <+48>:	mov    eax,0x0
   0x000000000000117e <+53>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000001182 <+57>:	xor    rdx,QWORD PTR fs:0x28
   0x000000000000118b <+66>:	je     0x1192 <main+73>
   0x000000000000118d <+68>:	call   0x1050 <__stack_chk_fail@plt>
   0x0000000000001192 <+73>:	leave  
   0x0000000000001193 <+74>:	ret  

with volatile:
   0x000000000000114d <+4>:	push   rbp
   0x000000000000114e <+5>:	mov    rbp,rsp
   0x0000000000001151 <+8>:	sub    rsp,0x20
   0x0000000000001155 <+12>:	mov    rax,QWORD PTR fs:0x28
   0x000000000000115e <+21>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001162 <+25>:	xor    eax,eax
   0x0000000000001164 <+27>:	mov    DWORD PTR [rbp-0x14],0x1
   0x000000000000116b <+34>:	mov    DWORD PTR [rbp-0x10],0x2
   0x0000000000001172 <+41>:	mov    DWORD PTR [rbp-0xc],0x3
   0x0000000000001179 <+48>:	mov    rax,QWORD PTR [rbp-0x14]
   0x000000000000117d <+52>:	mov    QWORD PTR [rbp-0x20],rax
   0x0000000000001181 <+56>:	mov    eax,DWORD PTR [rbp-0xc]
   0x0000000000001184 <+59>:	mov    DWORD PTR [rbp-0x18],eax
   0x0000000000001187 <+62>:	mov    eax,0x0
   0x000000000000118c <+67>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000001190 <+71>:	xor    rdx,QWORD PTR fs:0x28
   0x0000000000001199 <+80>:	je     0x11a0 <main+87>
   0x000000000000119b <+82>:	call   0x1050 <__stack_chk_fail@plt>
   0x00000000000011a0 <+87>:	leave
   0x00000000000011a1 <+88>:	ret
*/

