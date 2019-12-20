# CTF

### Android Reversing

Connect your Android device in debug mode.

Install an app ``` adb install asdf.apk ```

Uninstall an app ``` adb uninstall com.abhay.asdf ```

View logs ``` adb logcat ```

Copy files to device ``` adb push /machine /mobile ```

List all packages on device ``` adb shell pm list packages ```

Copy files from device ``` adb pull /data/app/asdf.apk /machine ```
