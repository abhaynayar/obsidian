#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    void *a = malloc(1);
    void *b = malloc(1);
    void *c = malloc(1);

    free(a);
    free(b);
    free(c);

    void *d = malloc(1);
    void *e = malloc(1);
    void *f = malloc(1);

    return 0;
}

