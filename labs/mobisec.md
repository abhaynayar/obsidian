# MOBISEC

> Prof. Yanick Fratonio
> [https://mobisec.reyammer.io/](https://mobisec.reyammer.io/)

[MOBISEC CTF Challenges]()

## 1 - Welcome!
## 2 - Quick History on Smartphones
## 3 - Intro to app development

Languages used to develop android apps:
- Java
- C/C++
- Kotlin

Android apps live in the context of Android framework
- Android framework exposes a lot of APIs

APIs are useful for the app to:

1. interacting with the outside world.
2. interact with the android framework.

Android APIs

- Extension to Java SDK APIs
- Android APIs are implemented within the android framework

<pre>
+-------------------------------+
|                               |
|        Systems Apps           |
|                               |
+-------------------------------+
|                               |
|     Java API framework        |
|                               |
+-------------------------------+
|                |              |
|  Native C/C++  |   Android    |
|  Libraries     |   Runtime    |
|                |              |
+-------------------------------+
|                               |
| Hardware Abstraction Layer    |
|                               |
+-------------------------------+
|                               |
|          Linux Kernel         |
|                               |
+-------------------------------+
</pre>

Example of APIs:

- [HTTP request](https://developer.android.com/reference/java/net/HttpURLConnection)
- [Log message](https://developer.android.com/reference/android/util/Log)
- [Access to GPS/location](https://developer.android.com/reference/android/location/LocationManager.html#requestLocationUpdates)

Android framework APIs:

- Too many to be enumerated
- Massive documentation by Google
	- https://developer.android.com/docs/
	- https://developer.android.com/guide/
	- https://developer.android.com/reference/
- Google for "android &lt;apinameyouneverheardabout&gt;"

Package name

- Acts as a unique identifier across the system.
- Constraints
	- No two apps can have the same package name in an Android device at the same time.
	- No two apps on the store can have the same package name.

Basics

- No "main" function.
- Event driven => register a listener, callback invoked later.
- Apps built as a combination of components.

Component types

1. [Activity](https://developer.android.com/reference/android/app/Activity): a screen that the user can see.
2. Service: performs an action in the background.
3. Broadcast Receiver: respond to system-wide event.
4. Content Provider: manage shared set of app data (sqlite).

Intents

- Used for talking between components.
- Use cases: starting another activity, sending data to another activity.

Types of Intents

- Explicit: specify component to talk with.
- Implicit: specify type of action and data.

Intent Filters

- A way for apps to declare the intents they can handle.
- System knows apps that can handle an invoked intent (ex. link can be opened by various browsers).

Android framework versions / [API](https://developer.android.com/guide/topics/manifest/uses-sdk-element#ApiLevels) levels:

- Each API builds on previous versions in an additive way.
- Old APIs are deprecated but rarely removed.
- New Android versions are backward-compatible.
- Each device runs one Android framework version.
- Minimum API level: Each app needs to specify which versions it can work on.
- Target API level: For which the app was designed and tested (ideally, latest).

Android Manifest

- The most important file in an Android app. [~](https://developer.android.com/guide/topics/manifest/manifest-intro)
- Key information needed by the framework to run the app.

Manifest Components:

- Activities
- Services
- Intent Filters
- Minimum / Target SDK
- Permissions [~](https://developer.android.com/guide/topics/permissions/overview)

Android Studio (important paths):

- &lt;android-studio&gt;/bin/studio.sh
- ~/Android/Sdk/platforms-tools/{adb,fastboot}
- ~/Android/Sdk/build-tools/&lt;version&gt;/aap
- ~/.android/avd/\*
- ~/AndroidStudioProjects/&lt;name&gt;/app/build/outputs/apk/debug/app-debug.apk (If you don't find it: $ find -name "\*.apk")

## 4 - Intro to Android architecture and security

- Android is based on Linux.
- Every app has its own Linux user ID (they may share IDs using sharedUserId).
- Every app lives in its own security sandbox.

App installation

- Android framework creates a new linux user.
- Each app given a private directory (internal shared).

Binder

Crossing the bridge

- Binder: one of the main extensions of Android over Linux.
- Allows for RPC, IPC.

Binder RPC

<pre>
                                  +
                                  |
                Non-privileged    |   Privileged
                Process           |   process / service
                                  |
               +---------------+  |   +----------------+
               | Binder Proxy  |  |   |  Binder Stub   |
 User space    +---------------+  |   +----------------+
                                  |
+---------------------------------+------------------------+

 Kernel space           +--------------------+
                        |   Binder Driver    |
                        +--------------------+

                        +--------------------+
                        |    Linux Kernel    |
                        +--------------------+

</pre>

Binder internals

- ```/dev/binder```
- ioctl syscall

Managers

```bash
$ adb shell service list
...
android.view.autofill.IAutoFillManager
android.app.slice.ISliceManager
android.media.projection.IMediaProjectionManager
android.app.IActivityManager
...
```

Binder IPC

- High-level API: intents
- Low-level: Binder calls
- Steps (A calls B.X):
	1. A calls ```startActivity(new Intent(B.X))```.
	2. Binder Proxy relays that to Binder Driver.
	3. Binder Driver calls Binder Stub of privileged process.
	4. Binder Stub calls relevant method in ActivityManager.
	5. Call is returned back to the Binder Driver.
	6. Binder Driver forwards it to B's Binder Proxy.
	7. Activity B.X calls ```onCreate()```

Android permission system [~](https://developer.android.com/reference/android/Manifest.permission#SEND_SMS)

- Android framework has a long list of permissions.
- Example: ```android.permission.INTERNET```
- {READ,WRITE}_EXTERNAL_STORAGE: /sdcard (in the past removable)

```bash
generic_x86_arm:/sdcard $ ls -l
total 40
drwxrwx--x 2 root sdcard_rw 4096 2020-02-20 19:45 Alarms
drwxrwx--x 3 root sdcard_rw 4096 2020-02-20 19:44 Android
drwxrwx--x 3 root sdcard_rw 4096 2020-02-21 10:03 DCIM
drwxrwx--x 2 root sdcard_rw 4096 2020-02-20 19:45 Download
drwxrwx--x 2 root sdcard_rw 4096 2020-02-20 19:45 Movies
drwxrwx--x 2 root sdcard_rw 4096 2020-02-20 19:45 Music
drwxrwx--x 2 root sdcard_rw 4096 2020-02-20 19:45 Notifications
drwxrwx--x 2 root sdcard_rw 4096 2020-02-20 19:45 Pictures
drwxrwx--x 2 root sdcard_rw 4096 2020-02-20 19:45 Podcasts
drwxrwx--x 2 root sdcard_rw 4096 2020-02-20 19:45 Ringtones
```

RECEIVE\_BOOT\_COMPLETED

- System broadcasts "ACTION_BOOT_COMPLETED" on booting.
- Apps can use corresponding intent-filters to automatically start at boot.
- Useful to gain persistence (but requires a permission).

SYSTEM\_ALERT\_WINDOW

- Draw on top of other apps.
- Custom position, shape, content transparency.
- Leads to attacks: UI confusion, clickjacking, phishing, [Cloak & Dagger](https://www.youtube.com/watch?v=RYQ1i03OVpI&t=1s).

Permission Protection Levels [~](https://developer.android.com/guide/topics/permissions/overview#normal-dangerous)

- Normal: automatically grant permission at install time without user prompt (users can't revoke these permissions).
- Dangerous: prompt user to grant permission at run time.
- Signature: granted at install time if app signed by same certificate as app defining permission.
- Special: must include in manifest + send intent to user (Ex: SYSTEM\_ALERT\_WINDOW, WRITE\_SETTINGS).

Permission Granting

- Normal: nothing explicit required from the user.
- Dangerous: user prompt (API &gt;= 23: runtime, API &lt; 23: install time).
- Signature: certificate or user prompt (not supported by all third-party).

Permissions Groups

- Example: SMS: RECEIVE\_SMS, READ\_SMS, SEND\_SMS
- Other mappinngs over [here](https://developer.android.com/guide/topics/permissions/overview#permission-groups).

```xml
<uses-permission android:name="android.permission.SEND_SMS"/>
```

- Custom Permissions [~](https://developer.android.com/guide/topics/permissions/defining)
- System Permissions defined in the same [way](http://androidxref.com/8.1.0_r33/xref/frameworks/base/core/res/AndroidManifest.xml#566).
- Components Permission Enforcement (for specific components within an app).

Permission Enforcement Implementation

- Ways: Linux groups vs. explicit checks
- [Groups](http://androidxref.com/8.1.0_r33/xref/frameworks/base/data/etc/platform.xml#24): INTERNET = ```inet```, BLUETOOTH = ```be_net```
- Checks: service's code does a check

android:exported [~](https://developer.android.com/guide/topics/manifest/activity-element#exported)

- Default value is false.
- If component defines an intent-filter, then default value is true.
- Can be set explicitly, if not, default policy kicks in.

## 5 - Read-World Android apps

App signing

- Each app signed with a certificate.
- Certificate = public key + metadata
- Owner holds the private key.

Primitives

- sign(MSG,PRIV) ~> SIGN
- verify(MSG,SIGN,PUB) ~> VALID / INVALID

- Certificate need not be signed by certificate authority.
- Certificate can be self-signed (like SSL, but SSL isn't trusted by default).
- Purpose: distinguish, not identify (system vs. normal apps for signature permissions).
- SSL: website is legitimate (through chain of certificates till CA which the browser trusts).

android:shareUserId [~](https://developer.android.com/guide/topics/manifest/manifest-element#uid)

- Apps can request to be assigned the same Linux user ID only if their certificates are the same.
- Both apps can access each others internal storage, components.

```xml
android:shareUserId="com.mobisec.shareduser"
```

Resources [~](https://developer.android.com/guide/topics/resources/providing-resources)

- Additional files and static content that the app uses.
- drawable, layout, raw
- values: {arrays, colors, strings}

Resources under the hood

```xml
# smali code
const v4, 0x7f07002b

# res/values/strings.xml
<string name="secret_string">Juicy Secret</string>

# res/values/public.xml (it specifies the mapping)
<public type="string" name="secret_string" id="0x7f07002b" />
```

RunTime.exec() [~](https://developer.android.com/reference/java/lang/Runtime)

- Analogous to C's system() or Python's os.system()
- Runtime.exec("cp ../flag /sdcard/leaked-flag.txt")

Reflection [~](https://developer.android.com/reference/java/lang/reflect/package-summary)

- To play with java objects.
- Bypass access modifiers.
- Enumerate methods / fields of a class.
- Use-case:
	- Java objects to JSON reporesentation: [gson](https://github.com/google/gson)
	- Obfuscation: ```peppa.getClass().getMethod("pig").invoke(peppa);```


Dynamic Code Loading

- Apps can load code at run-time.
- From: file-system, embedded, just-downloaded.
- Obfuscation [paper](http://www.s3.eurecom.fr/~yanick/publications/2014_ndss_android-remote-code-execution.pdf) by author.

```java
Class<?> cls = (Class<?>) classloader.loadClass("com.mobisec.Peppa");
Method m = cls.getMethod("pig");
```

Serialization

- Serialized version of objects encode data about the objects, not the definition of the class.
- Objects need to be serialized before they are sent via Binder.
- Two main [interfaces](https://www.javacodegeeks.com/2014/01/android-tutorial-two-methods-of-passing-object-by-intent-serializableparcelable.html): [Parcelable](https://developer.android.com/reference/android/os/Parcelable), [Serializable](https://developer.android.com/reference/java/io/Serializable)


## 6 - More on Key Android Aspects

Activity

- startActivity(intent)
- New: activities can also get an answer / result.

```java
# A.X

Intent i = new Intent(...);
int requestCode = 400;
startActivityForResult(i, requestCode);

# B.Y

onCreate() {
  Intent resInt = new Intent();
  ...
  setResult(Activity.RESULT_OK, resInt);
  finish();
}

# don't know what this means

onActivityResult(int requestCode, int resultCode, Intent data) {
  // check requestCode and resultCode
  ...
}

```

Service

- No analogous startActivityForResult(), but can use broadcast intents.
- To start a service:

```java

// Intent must be explicit (not required for activities since they have a chooser dialog)
Intent i = new Intent(...);

startService(i)

```

Types of Services [~](https://developer.android.com/guide/components/services)

- Background ```startService() → S.onCreate() → S.onStartCommand()```
- Foreground ```startService() + startForeground() → S.onCreate() → S.onStartCommand()```
- [Bound](https://developer.android.com/guide/components/bound-services) ```bindService() → S.onCreate() → S.onBind()```


Three ways of implementing:

1. Local service (intra-app)
2. Using a messenger.
3. Using AIDL.

Inter-Process Services via Messengers [~](https://developer.android.com/guide/components/bound-services)

```java
public IBinder onBind(Intent intent) {
    mMessenger = new Messenger(new IncomingHandler(this));
    return mMessenger.getBinder();
}

static class IncomingHandler extends Handler {
    IncomingHandler(Context context) { ... }

    @Override
    public void handleMessage(Message msg) {
        switch (msg.what) {
             case MSG_SAY_HELLO:
            ...
		}
	}	
}

private ServiceConnection mConnection = new ServiceConnection() {
  public void onServiceConnected(ComponentName className, IBinder service) {
    mService = new Messenger(service);
    mBound = true;
  }
  ...
};

bindService(new Intent(...), mConnection, Context.BIND_AUTO_CREATE);

Message msg = Message.obtain(null, MessengerService.MSG_SAY_HELLO, 0, 0);
mService.send(msg);
```

Broadcast Intent and Receivers

- sendBroadcast(intent);
- Relevant broadcast receivers will be woken up.
- Register via manifest and intent-filter or at run-time (only for broadcast receivers).

```java
MyReceiver customRec = new MyReceiver();
IntentFilter intFil = new IntentFilter("com.some.action");
registerReceiver(customRec, intFil);
```

Bundles

- Pass data around via intents.
- Wrapper around key-value store.
- key: String, value: any serializable class

```java
bundle.putString("flag", "hereismyflag");
bundle.putInt("num", 42)
```

```java
intent.putExtra("flag", "flagvalue");
intent.putExtra("num", 42);

intent.getExtras() ~> Bundle object
```

PackageManager

```
PackageManager pm = context.getPackageManager();
List<ResolveInfo> list = pm.queryIntentServices(implicitIntent, 0);
ResolveInfo serviceInfo = list.get(0); // if any
ComponentName component = new ComponentName(
   serviceInfo.serviceInfo.packageName,
   serviceInfo.serviceInfo.name);
```

## 7 - Messing with Android apps

![](mobisec/compilation.png)

Apk is a zip file (kinda)

```bash
$ unzip app.apk
```

Java / Dalvik bytecode

- Cannot be run by processor.
- Can be run by VM (JVM/DVM).
- DVM: code that your processor can run, takes Dalvik bytecode as input and executes intended behaviour.
- We use virtual machine so that the same code can run across multiple devices / architectures (DVM is custom).
- There is on security benefit to having a virtual machine.

Dalvik bytecode verifier

- Checks if the bytecode is well-formed.
- Dalvik is easy to disassemble.
- Therefore bad for the bad guys.

What can bad guys do then?

- You can still obfuscate (Reflection).
- You can also load code dynamically.
- Or use native code (no such thing as native code verifier, Google NaCl doesn't apply).

Dalvik bytecode

- Knows about OO concepts.
- Dest-to-src syntax.
- Types: V void, B byte, S short, C char, I int, Z boolean.
- Classes: L&lt;fullyqualifiedclassname&gt; (ex.: Landroid.content.Intent;).
- The bytecode is nicely split in "methods" (.smali files).
- Dalvik is register-based.
- Each method has its own register "frame".
- Methods' args are placed in the last registers of the frame.
- If a method is non-static, the first argument is "this".

Register frame

Consider a method s.t.
- it takes 3 arguments
- its register frame has 6 registers

The method will use
- Registers v0, v1, v2, v3, v4, v5
- Arguments are placed in v3, v4, v5

Register model

- Different from CPU registers.
- Not shared across methods.
- Can contain values and references though.

Examples

```java
int pig(int x) {
    return 2*x;
}
```

```dalvik
.method pig(I)I
    .registers 3

    mul-int/lit8 v0, v2, 0x2

    return v0
.end method
```

```
int foo(int a, Peppa p) {
    int b = p.pig(a);
    return b;
}
```

```
.method foo(ILcom/mobisec/Peppa;)I
    .registers 5

    invoke-virtual {v4, v3}, Lcom/mobisec/Peppa;->pig(I)I
    move-result v0

    add-int v1, v3, v0
    return v1
.end method
```

Dalvik instructions [~](https://source.android.com/devices/tech/dalvik/dalvik-bytecode)

```dalvik
; moving
const v5, 0x123
move v4, v5

; arithmetic
add-int v1, v3, v0
mul-int/lit8 v0, v2, 0x2

; invocation
invoke-virtual {v4, v3}, Lcom/mobisec/Peppa;->pig(I)I
invoke-static ...
invoke-{direct, super, interface} ...

; return
move-result v5

; set / get
iget, iget-object, ...
iput, iput-object, ...
sget, sput ... (for static fields)

; new object
new-instance v2, Lcom/mobisec/Peppa;

; control flow
if-ne v0, v1, :label_a
...
:label_a
...
goto :label_b

; meta
filled-new-array
```

Which component executes Dalvik?


1. In the past (uptil Android 4.4)
	- DVM, libdvm.so
	- When about to execute a method, compile and run it.
	- Compilation is done "on-demand" (Just-in-time).
	- Compiled code stored in cache.

2. Then we got Android ART (introduced in Android 5)
	- Android Run-Time replaced the old DVM (optional in Android 4.4).
	- Ahead-of-time compilation (at app installation time).
	- App boot and execution are faster, but more space required on RAM & DISK.
	- Installation takes much longer, bad repercussion on system upgrades, could take ~15 minutes.

3. New version of ART (introduced in Android 7)
	- Profiles an app and precompiles only the "hot" methods (most likely to be used).
	- Other parts of the app are left uncompiled.
	- Automatically precompiles methods "near to be used."
	- Precompilation only happens when the device is idle and charging.
	- Quick path to install / upgrade.

![](mobisec/art.png)

ODEX: optimized DEX

- dex →  _dexopt_ →  ODEX
- Faster to boot and run.
- Most system apps that start at boot are ODEXed.
- ODEX is an additional file, next to an APK.
- Device dependent.

Analogous of ODEX for ART

- The new ART uses two formats.
- The ART format (.art files):
	- pre-initialized classes / objects.
	- only one file: **boot.art**
	- contains pre-initialized memory for most of the Android framework.
- The OAT files:
	- compiled bytecode to machine code wrapped in an ELF file.
	- can contain one or more DEX files (actual Dalvik bytecode).
	- obtained with _dex2oat_ (usually run at install time).
	- you still have **.odex** files.
	- **.odex** files are OAT-formatted files!
	- one important file: **boot.oat**
	- all traditional ODEX files are OAT files.
	- can be inspected with **oatdump**.

When a new app starts

- All app processes are created by forking Zygote (init, template).
- Optimization trick: **boot.oat** is already mapped in memory, no need to reload the framework!

![](https://en.wikipedia.org/wiki/File:ART_view.png)

More information

- [stackoverflow](http://newandroidbook.com/files/Andevcon-ART.pdf)
- [newandroidbook](http://newandroidbook.com/files/Andevcon-ART.pdf)
- [ctf-challenge](http://reyammer.blogspot.com/2016/03/from-android-art-binary-only-to-dex-yes.html)

Tools time!

- ```unzip app.apk```
	- AndroidManifest.xml (compressed)
	- classes.dex
	- resources (compressed)

- 


----

# MOBISEC CTF Challenges

## app dev

### justlisten

> The flag is announced on the system with a broadcast intent with action com.mobisec.intent.action.FLAG_ANNOUNCEMENT. The flag is in the Intent's bundle, under the "flag" key.

So, essentially, we need to find how to create a broadcast receiver, and log the intent bundle "flag" after we receive it.

The emulator used in the analysis system is **Android 9.0 (Google Play), API 28**. According to the official Android [documentation](https://developer.android.com/guide/components/broadcasts#changes-system-broadcasts):

- Beginning with Android 8.0 (API level 26), the system imposes additional restrictions on manifest-declared receivers.
- If your app targets Android 8.0 or higher, you cannot use the manifest to declare a receiver for most implicit broadcasts (broadcasts that don't target your app specifically). You can still use a **context-registered** receiver when the user is actively using your app.

At first I decided to try receiving the broadcast the traditional way by lowering the targetSdkVersion in app:build.gradle, but it doesn't show any output in logcat that way.

AndroidManifest.xml

```
<receiver android:name=".MyBroadcastReceiver"  android:exported="true">
    <intent-filter>
        <action android:name="com.mobisec.intent.action.FLAG_ANNOUNCEMENT" />
    </intent-filter>
</receiver>
```

MyBroadcastListener.java

```
public class MyBroadcastListener extends BroadcastReceiver {
    private static final String TAG = "ABHAY";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(TAG,"In MyBroadcastListener.java");
        Bundle bundle = intent.getExtras();
        if (bundle != null) {
            for (String key : bundle.keySet()) {
                Log.e(TAG, key + " : " + (bundle.get(key) != null ? bundle.get(key) : "NULL"));
            }
        }
    }
}
```

----

So we need to learn how to handle it from API >= 26.
