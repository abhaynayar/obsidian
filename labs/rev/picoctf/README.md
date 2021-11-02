## ARMssembly1

Assemble the listing:

```
$ aarch64-linux-gnu-gcc -static -c chall_1.S
```

Decompile the object file:

```
#include<stdlib.h>

int func(int param_1) {
  return 0xd2a - param_1;
}


int main(undefined8 param_1,long param_2) {
  int iVar1;

  iVar1 = atoi(*(char **)(param_2 + 8));
  iVar1 = func(iVar1);
  if (iVar1 == 0) {
    iVar1 = puts("You win!");
  }
  else {
    iVar1 = puts("You Lose :(");
  }
  return iVar1;
}
```

