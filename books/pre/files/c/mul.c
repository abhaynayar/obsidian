#include <stdio.h>

int main() {
    unsigned int b=1;
    unsigned int c = 1337*b;
    printf("%u",c);
}

/*
 * for 10*23, the product is directly used in assembly
 * for a*b, one operand is moved into eax and other is used in imul
 * for 16*b, weird shifts and additions are performed to get 16 (?)
 */

