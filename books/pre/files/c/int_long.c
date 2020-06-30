#include <stdio.h>

int main() {
    long y=2;
    long long z=3;
    int x=1;
}

/*

I wanted to see how ints and longs are treated differently.

            0x0000112d      55             push rbp
            0x0000112e      4889e5         mov rbp, rsp
            0x00001131      c745ec010000.  mov dword [rbp - 0x14], 1
            0x00001138      48c745f00200.  mov qword [rbp - 0x10], 2
            0x00001140      48c745f80300.  mov qword [rbp - 8], 3
            0x00001148      b800000000     mov eax, 0
            0x0000114d      5d             pop rbp
            0x0000114e      c3             ret

for the 2&3 qword (8-bytes) is used, while for 1 dword (4-bytes) is used.
changing the order of declaration in c changed it in assembly as well but the offset from rbp remains the same.

            0x00001131      48c745f00200.  mov qword [rbp - 0x10], 2
            0x00001139      48c745f80300.  mov qword [rbp - 8], 3
            0x00001141      c745ec010000.  mov dword [rbp - 0x14], 1

according to cpp standard "long long is at least as wide as long" so perhaps only when the value in it exceeds the range of long, we'll see a difference.

*/

