
# CTF


## ![](https://img.icons8.com/ios/50/000000/android-os.png) Android Reversing

### adb

Connect your Android device in debug mode.

Install an app ``` adb install asdf.apk ```

Uninstall an app ``` adb uninstall com.abhay.asdf ```

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

## ![](https://img.icons8.com/dotty/80/000000/binary-file.png) Binary Exploitation

### Initial checks
- [ ] file
- [ ] strings
- [ ] checksec
  
### pwntools

Setting up ``` pwn template ./<binary> --host 127.0.0.1 --port 1337 ```

Debug with gdb ``` io = gdb.debug('./<binary>', 'b main') ```

### Return Oriented Programming

#### Finding function addresses
``` nm <binary> | grep ' t ' ```

``` (gdb) info functions ```

#### 

### Format String Attacks

Offset notation ``` %6$x ```
#### Reading from arbritrary address
1. Get address of string to be read. ``` rabin2 -z <binary> ```
2. Find the offset from the stack where the input is stored to do this %x. then %x.%x. then %x.%x.%x. and so on until you     see the ascii values 25782e.
3. once you know the offset, store the address to be read at that
   offset by typing it in as the first thing in the buffer and then
   use the offset you found out to go read in that address.
```
python -c 'print "\xef\xbe\xad\xde%6$s"' | ./<binary>
```

## ![](https://img.icons8.com/wired/64/000000/lock-2.png) Crypto

### Try out Cryptopals

https://cryptopals.com/

### RSA

If ```n``` is given, try checking if it is already factored at http://factordb.com


## ![](https://img.icons8.com/ios/50/000000/google-web-search.png) Forensics
### Initial checks
- [ ] file
- [ ] xxd
- [ ] strings
- [ ] binwalk
- [ ] foremost
- [ ] johntheripper
- [ ] [cryptograms](https://quipqiup.com/)

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
