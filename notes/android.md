## ► android

### adb

- Connect your Android device in debug mode (or use Genymotion).
- Installing an app `adb install asdf.apk`
- _Sometimes installing an app might not work because of permissions_
- Uninstalling an app `adb uninstall com.abhay.asdf`
- View logs `adb logcat`
- Copy files to device `adb push /machine /mobile`
- List all packages on device `adb shell pm list packages`
- Copy files from device `adb pull /data/app/asdf.apk /machine`

### apktool

- Disassemble an app `apktool d <apk-file>`
- Build a disassembled file `apktool b <decompiled-directory>`
- Sign the built app using the following commands or uber-apk-signer.

```
$ keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
$ jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore my_application.apk alias_name
```

### drozer

Here is the <a href="https://labs.f-secure.com/assets/BlogFiles/mwri-drozer-user-guide-2015-03-23.pdf">manual</a>. Here is the GitHub <a href="https://github.com/FSecureLABS/drozer">repo</a>. First we need to install Java 6 using this <a href="https://gist.github.com/senthil245/6093389">link</a>.

```
# installing drozer on ubuntu
$ wget https://github.com/mwrlabs/drozer/releases/download/2.4.4/drozer_2.4.4.deb
$ sudo apt install ./drozer_2.4.4.deobf

# installing drozer agent on your phone
$ wget https://github.com/mwrlabs/drozer/releases/download/2.3.4/drozer-agent-2.3.4.apk
$ adb install drozer-agent-2.3.4.apk 

# forward a tcp port on your pc
$ adb forward tcp:31415 tcp:31415

# then turn on embedded server using the drozer app
$ drozer console connect

# a few useful drozer commands
dz&gt; list/ls package # to see all modules
dz&gt; run app.package.list -f revels

# list attack surface
dz&gt; run app.package.attacksurface com.mit.mitrevels20

# list debuggable apps
dz&gt; run app.package.debuggable

# installing modules
dz&gt; module search -d # search (show module descriptions)
dz&gt; module install keyword # https://github.com/FSecureLABS/drozer-modules
dz&gt; shell # launch shell in context of the current app
dz&gt; run app.activity.info -a com.hacker101.level13 -i -u
dz&gt; run app.package.manifest com.hacker101.level13 


dz&gt;  module install mwrlabs.develop
You do not have a drozer Module Repository.
Would you like to create one? [yn] y
Path to new repository: /home/abhay/Desktop/tools/android/drozer
Initialised repository at /home/abhay/Desktop/tools/android/drozer.

Processing mwrlabs.develop... Done.
Successfully installed 1 modules, 0 already installed.
```

### Hacking with drozer

You can then download [sieve](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk") (an intentionally vulnerable password manager) and start practicing. I recommend you use the app and get around it by creating some data. It will help you when you are hacking content ids.

```
# install app on phone
$ adb install sieve.apk

# find package name
dz&gt; run app.package.list -f sieve
com.mwr.example.sieve (Sieve)

# get package info
dz&gt; run app.package.info -a com.mwr.example.sieve
Package: com.mwr.example.sieve
  Application Label: Sieve
  Process Name: com.mwr.example.sieve
  Version: 1.0
  Data Directory: /data/user/0/com.mwr.example.sieve
  APK Path: /data/app/com.mwr.example.sieve-C-N8JWub07PC-5vtVMNjKg==/base.apk
  UID: 10305
  GID: [3003]
  Shared Libraries: [/system/framework/org.apache.http.legacy.boot.jar]
  Shared User ID: null
  Uses Permissions:
  - android.permission.READ\_EXTERNAL\_STORAGE
  - android.permission.WRITE\_EXTERNAL\_STORAGE
  - android.permission.INTERNET
  Defines Permissions:
  - com.mwr.example.sieve.READ\_KEYS
  - com.mwr.example.sieve.WRITE\_KEYS

# finding attack surface
dz&gt; run app.package.attacksurface com.mwr.example.sieve
  3 activities exported
  0 broadcast receivers exported
  2 content providers exported
  2 services exported
    is debuggable

# get exported activities
dz&gt; run app.activity.info -a com.mwr.example.sieve
Package: com.mwr.example.sieve
  com.mwr.example.sieve.FileSelectActivity
  com.mwr.example.sieve.MainLoginActivity
  com.mwr.example.sieve.PWList

# run an activity (PWList) directly using:
dz&gt; run app.activity.start --component com.mwr.example.sieve com.mwr.example.sieve.PWList

# list accessible content URIs
dz&gt; run scanner.provider.finduris -a com.mwr.example.sieve

# database based content URIs
dz&gt; run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --vertical
dz&gt; run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "'"
dz&gt; run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --selection "'"
dz&gt; run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM SQLITE_MASTER WHERE type='table';--"
dz&gt; run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/--projection "*FROM Key;--"

# filesystem based content URIs
dz&gt; run app.provider.read content://com.mwr.example.sieve.FileBackupProvider/etc/hosts
dz&gt; run app.provider.download content://com.mwr.example.sieve.FileBackupProvider/data/data/com.mwr.example.sieve/databases/database.db /home/abhay/Desktop/database.db
Written 4096 bytes
```

### objection

It can be run without having to patch. I tried patching an app but it didn't run (maybe it was tamper-proof). You first need to be rooted, then transfer the frida-server binary to your android device and run it. Then on your PC:

`$ objection --gadget="org.telegram.messenger" explore`

Some useful objection commands:

```
# env
# android sslpinning disable
# android keystore list
# android root disable
```

### r2

```
$ rafind2 -ZS permission AndroidManifest.xml
$ rabin2 -I classes.dex
$ r2 classes.dex

&gt; izq    ; rabin2 print string quietly
&gt; izj~{} ; json formatted prettyprint
&gt; ic     ; class names and their methods
&gt; ii     ; imported methods
&gt; f~+verify  ; grep flags by "verify"
&gt; s sym.method.blah ; seek to method
&gt; pdf    ; print disassembly
```

#### r2frida

```
$ r2 frida://[PID]
```

### Network Capture

First install <a href="https://www.androidtcpdump.com/">tcpdump</a> on your phone (see <a href="android3.html">here</a>).

```
# tcpdump -i wlan0 -s0 -w - | nc -l -p 11111
$ adb forward tcp:11111 tcp:11111
$ nc localhost 11111 | wireshark -k -S -i -
```

### Java Version

One of the most essentials tools are the Android SDK tools which can be
found once you install <a href="https://developer.android.com/studio">Android Studio</a>. An important thing to keep in mind
is Java versions, I won't go into depth here, but having the wrong version
of Java for the wrong tool might mess things up. So it's good to know how
to keep several Java versions and switch between them when required. 

```
# choose java and javac version to use
$ sudo update-alternatives --config java
$ sudo update-alternatives --config javac

# add these lines to your ~/.profile
export JAVA_HOME=/usr/lib/jvm/&lt;java-version&gt;
export PATH=$PATH:/usr/lib/jvm/&lt;java-version&gt;/bin
```

### Burp system-wide CA
In order to intercept HTTPS as well, we need a system-wide CA: <a href="https://blog.ropnop.com/configuring-burp-suite-with-android-nougat/#install-burp-ca-as-a-system-level-trusted-ca">link</a>, <a href="https://stackoverflow.com/questions/13089694/adb-remount-permission-denied-but-able-to-access-super-user-in-shell-android">link</a>. First download the burp CA and start the emulator as writable (always):

```
# convert burp CA to work with android
$ openssl x509 -inform DER -in cacert.der -out cacert.pem
$ openssl x509 -inform PEM -subject\_hash\_old -in cacert.pem |head -1
$ mv cacert.pem 9a5ba575.0

# starting and applying the CA to emulator
$ ./emulator -avd Nexus\_S\_API\_28 -writable-system

$ adb root
$ adb remount

# if remounting does not work, look into android2.html
# you have to remount / instead of /system through su
$ adb push 9a5ba575.0 /sdcard
9a5ba575.0: 1 file pushed. 0.0 MB/s (1375 bytes in 0.028s)

$ adb shell
generic\_x86\_arm:/ # mv /sdcard/9a5ba575.0 /system/etc/security/cacerts/
generic\_x86\_arm:/ # chmod 644 /system/etc/security/cacerts/9a5ba575.0

$ adb reboot
```

Even after getting a system-wide CA, we might not be able to intercept all
traffic due to SSL pinning. In case neither of the above methods work, you
can patch the app to make only HTTP requests, and then convert them into
HTTPS requests while by intercepting them through a proxy.

#### Useful adb commands

```
$ adb push /path/in/phone
$ adb pull /file/from/phone
$ adb logcat

# for multiple devices
$ adb devices
$ adb install level13.apk
$ adb shell pm list packages
$ adb uninstall com.hacker101.level13

# if only a single emulator and a single physical device is connected
$ adb -e install level13.apk
$ adb -d install level13.apk

# screenshot through adb
$ adb shell screencap /sdcard/image.png
$ adb pull /sdcard/image.png
```

### Pulling and decompiling

You can either pull apps that you have installed on your phone or get them
from various websites.

```
$ adb shell pm list packages | grep evernote
$ adb shell pm path com.evernote
$ adb pull /data/app/com.evernote-p3FsCe99KNBxtacyNxmFfw==/base.apk
```

Once we have the apk we can decompile and see it using jadx-gui.

```
$ jadx-gui --deobf --deobf-min 3 base.apk
```

Things to keep in mind:

You can control click on most things to see their definitions.
It is a good practice to save projects in jadx-gui.
One of the useful features within the interface is the search functionality which you can use to check certain keywords in code.
To find other places a method is used, right-click &gt; Find Usage.

If jadx-gui fails to decompile any methods, we can always try other combinations such as <b>dex2jar</b> for DEX to JAR conversion and then decompile it using somthing like CFR.

```
$ unzip myapp.apk
$ sh d2j-dex2jar.sh classes.dex
$ java -jar cfr-0.149.jar classes-dex2jar.jar &gt; out

# or use jadx
$ jadx myapp.apk -d out
```

### Using IntelliJ IDE

In order to debug the decompiled code, an IDE is helpful to create a
smooth workflow. In this IDE, we can create a new Android project and fill
it with our decompiled code. So first, we will unzip and decompile our APK.

```
$ unzip snake.apk -d snake
$ cd snake
$ jadx -d out classes.dex
$ cd out/sources
```

Once we have the decompiled codes, create an Android project in the IDE
and delete the com.example.app under java sources. then copy the above
folder in its place that we have just cd'ed into. Furthermore, you may
require adjustments to make the code work in harmony.

### Reversing native libraries

List the Java native functions.

```
...lib/x86\_64	$ readelf -W -s libnative-lib.so | grep Java
115: 00008de0    15 FUNC    GLOBAL DEFAULT   13 Java\_com\_r4hu1\_snakefinals\_SnakeEngine\_integerFromJNI
194: 00008df0   414 FUNC    GLOBAL DEFAULT   13 Java\_com\_r4hu1\_snakefinals\_SnakeEngine\_stringFromJNI
```

Then you can use IDA to decompile them. It is recommended to use 64 bit ones as you can decompile them using IDA's demo version.

`$ ida libnative-lib.so`

### Patching apps

Decompilation helps you understand the code, but sometimes you need to modify the smali code.

```
# this will create a folder with name three in the same directory
$ apktool d three.apk

# once you are done modifying the smali code you can build it back to an apk
# the build apk will be found in ./three/dist
$ apktool b three

# you can either sign and run the apk on your physical device
keytool -genkey -v -keystore my-release-key.keystore -alias alias\_name -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore my\_application.apk alias\_name

# or you can run it on your emulator using android studio &gt; Generate Signed Bundle or APK
# I kept running into errors in both approached therefore I shifted to uber-apk-signer
# need to have jdk version &gt; 8

$ wget https://github.com/patrickfav/uber-apk-signer/releases/download/v1.1.0/uber-apk-signer-1.1.0.jar
$ java -jar uber-apk-signer-1.1.0.jar --apks /home/abhay/Desktop/shared/ctfs/pico19/android/three/dist
```

Things to keep in mind:
- Don't try to add certificates to apks which already have a certificate.
- If you are having trouble installing app, uninstall the previous version from your phone.
- Sometimes you might have to go to the settings and uninstall it for all users.

### Running an emulator

Running an avd from the command line:

```
$ emulator -list-avds
$ emulator -avd Pixel_2_API_28
```

I created a short (albeit, not so robust) bash function:

```
emulator () {
    cd /media/windows/shared/tools/android/sdk/emulator
    ./emulator -avd `./emulator -list-avds` # --writable-system
}
```

### Setting up frida for dynamic analysis

Remember to disable Magisk Hide in case you have it.
First download frida client for your PC:

```
$ pip install frida-tools
$ frida --version
12.8.11
```

Then download the frida-server for your device. It can be found <a href="https://github.com/frida/frida/releases">here</a>.
To know your own ABI issue the following command:

```
$ adb shell getprop ro.product.cpu.abi
```

If you're using an AVD, download one which doesn't have the "Play Services" icon (required for root).
Rooting is important for frida injection, emulators are mostly rooted by default.

```
# rooting emulated device
$ adb root

# in case you have a physical device and rooted through Magisk
# go into Magisk Manager and grant access to shell after trying
# su command through adb once, also disable Magisk Hide.

# push frida-server binary into the phone and run:
$ adb push frida_server /data/local/tmp
$ adb shell /data/local/tmp/frida_server
```

### Useful frida commands

```
$ frida-ps -U  # list of running processes (-U) use connected USB devices or emulator
$ frida-ps -Uai # get all apps (-a) currently installed (-i)

# once you have started the app, type %resume to start the main thread
$ frida-trace -U com.android.chrome -i "open" # start tracing low-level library calls (in this case, open)
$ frida -U com.android.chrome # hooks into a process and gives you a command line interface
$ frida -U -l myscript.js com.android.chrome # load scripts, gets called when you reopen app

myscript.js

```javascript
Java.perform(function () {
    var Activity = Java.use("android.app.Activity");
    Activity.onResume.implementation = function () {
        console.log("[*] onResume() got called!");
        this.onResume();
    };
});
```

```
# get your android version
[Android Emulator 5554::com.twitter.android.lite]-&gt; Java.androidVersion
"9"

# list all classes
[Android Emulator 5554::com.twitter.android.lite]-&gt;
Java.perform(function(){
	Java.enumerateLoadedClasses({
		"onMatch":function(className){
			console.log(className)
		},"onComplete":function(){}
	})
})
```

### Setting up a proxy

For an AVD:

```
$ emulator @Nexus\_5X\_API\_23 -http-proxy 127.0.0.1:8080
```

Connect your phone to your laptop over USB.

Connect to a WiFi network even if you don't have internet conenction.

```
$ adb reverse tcp:8080 tcp:8081
```

Within Burp in your computer, under Proxy &gt; Options: add a new listener
on <b>all interfaces</b> on an unused port such as <b>8081</b>.

Change your WiFi proxy settings to point to localhost:8080, which will
then be routed to your computer's 8081 which will then be routed to the
internet through Burp.

SSL pinning can be overcome in two ways: patch the app to remove the check
method, or dynamically re-implement the check method.

For dynamic re-implementation we can use <a href="https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/">this</a> script.

```
$ cp cacert.der burpca-cert-der.crt
$ adb push burpca-cert-der.crt /data/local/tmp/cert-der.crt
$ frida -U -f com.app.mobile -l frida-android-repinning.js --no-pause
```

Busybox: it gives you a lot of linux tools that are not a part of android.
It doesn't require rooting your phone. For example using text editors.

```
# Installing busybox
$ wget https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-armv8l
$ adb push busybox-armv8l /data/local/tmp
busybox-armv8l: 1 file pushed. 17.6 MB/s (1148524 bytes in 0.062s)

$ adb shell
adb:/ $ cd /data/local/tmp
adb:/data/local/tmp $ chmod 755 busybox-armv8l
adb:/data/local/tmp $ export PATH=$PATH:/data/local/tmp # temporary, since not rooted

# If you have root access
adb:/data/local/tmp $ cp busybox-armv8l /system/xbin
adb:/data/local/tmp $ cd /system/xbin
adb:/system/xbin $ busybox-armv8l --install .
```

