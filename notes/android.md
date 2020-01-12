## ► android

### Learn
- How to get flags out of APKs using ```strings``` (InCTF Nationals 2019)

### adb

Connect your Android device in debug mode (or use Genymotion).

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
