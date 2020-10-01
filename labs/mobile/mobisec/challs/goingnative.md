# goingnative

We first unpack the apk using apktool and then go ahead and decompile ```~/goingnative/lib/x86_64/libnative-lib.so```.

After we find the correspoing flag check method, it is relatively easy to decompile it.

```c
__int64 __fastcall Java_com_mobisec_gonative_FlagChecker_helloFromTheOtherSide(__int64 a1, __int64 a2, __int64 a3, int a4)
{
  __int64 v5; // r14
  __int64 v6; // r15
  char *v7; // rbp
  char dest[5]; // [rsp+Ah] [rbp-2Eh]
  char v10; // [rsp+Fh] [rbp-29h]
  unsigned __int64 v11; // [rsp+10h] [rbp-28h]

  v5 = a3;
  v11 = __readfsqword(0x28u);
  v6 = (*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a3, 0LL);
  if ( strlen((const char *)v6) == 12
    && a4 == 31337
    && *(_BYTE *)v6 == 110
    && *(_BYTE *)(v6 + 11) == 111
    && (v7 = dest, strncpy(dest, (const char *)(v6 + 1), 5uLL), v10 = 0, !strncmp("ative", dest, 5uLL))
    && *(_BYTE *)(v6 + 9) == 95
    && *(_BYTE *)(v6 + 6) == 95
    && *(_BYTE *)(v6 + 7) == 105
    && *(_BYTE *)(v6 + 8) == 115 )
  {
    LOBYTE(v7) = strcmp("so", (const char *)(v6 + 10)) == 0;
    (*(void (__fastcall **)(__int64, __int64, __int64))(*(_QWORD *)a1 + 1360LL))(a1, v5, v6);
  }
  else
  {
    (*(void (__fastcall **)(__int64, __int64, __int64))(*(_QWORD *)a1 + 1360LL))(a1, v5, v6);
    LODWORD(v7) = 0;
  }
  if ( __readfsqword(0x28u) != v11 )
    JUMPOUT(0x8A4LL);
  return (unsigned int)v7;
}
```

There is an extra zero that we're not able to see in the native decompiled code, but in the java decompilation, there is a check for a length of six which means we have to pad it by zero.

After some basic reversing we get the flag: ```MOBISEC{native_is_so-031337}```

