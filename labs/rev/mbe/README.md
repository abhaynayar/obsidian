## RPISEC - Modern Binary Exploitation

In `2_bombs/crackme0x04_win.exe`:

1. scanf takes string input
2. first byte of input extracted
3. put into sscanf(inp,"%d");
4. compared with 0xf

