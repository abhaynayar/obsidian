#include <stdio.h>

int main() {
    char *a = "ASDF";
    char b[] = "asdf";
}

/*

char* is stored in the text section and its address is pushed onto the stack:
lea    rax,[rip+0xe99]
mov    QWORD PTR [rbp-0x18],rax

char[] is stored on the stack immediately:
mov    DWORD PTR [rbp-0xd],0x66647361
mov    BYTE PTR [rbp-0x9],0x0

*/

