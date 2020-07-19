#include <stdio.h>
/*#define ASDF 10*/

int main() {
    printf("out");
#ifdef ASDF
    printf("in");
#endif
    printf("exit");
    return 0;
}

