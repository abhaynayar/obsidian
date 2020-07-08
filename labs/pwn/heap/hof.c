#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//$ gcc -ggdb -Wl,-z,norelro -o hof hof.c
char* target = "change_me";

int main() {
    char *input = malloc(10);
    printf("enter a string: ");
    scanf("%s", input);

    printf("input: %s\n",input);
    printf("target: %s\n",target);
    return 0;
}

