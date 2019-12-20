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


## ![](https://img.icons8.com/wired/64/000000/lock-2.png) Crypto

### Try out Cryptopals

https://cryptopals.com/

### RSA

If ```n``` is given, try checking if it is already factored at http://factordb.com


## ![](https://img.icons8.com/ios/50/000000/google-web-search.png) Forensics
### Initial checks
- [ ] file / trid
- [ ] xxd / hexedit
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
- extundelete
- testdisk
- volatility

### PCAP

- wireshark
- packettotal


## ![](https://img.icons8.com/ios/40/000000/binary-file.png) Binary Exploitation

### Initial checks

- [ ] strings <binary>
- [ ] strace / ltrace
- [ ] checksec <binary>

### Format String Attacks

Offset notation ``` %6$x ```
