# MOBISEC

> Prof. Yanick Fratonio
> [https://mobisec.reyammer.io/](https://mobisec.reyammer.io/)

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
- Google for "android <apinameyouneverheardabout>"

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

1. [Activity](https://developer.android.com/reference/android/app/Activity): a screen
2. Service: perform an action in the background
3. Broadcast Receiver: respond to systemr-wide event
4. Content Provider: manage shared set of app data (sqlite)

### Intents

- Talking between components
- Use cases: starting another activity, sending data to another activity

Types of Intents

- Explicit: specify component to talk with
- Implicit: specify type of action and data

Intent Filters

- A way for apps to declare the intents they can handle.
- The system knows it can invoke that intent (ex. link can be opened by various browsers)

Android framework versions / [API](https://developer.android.com/guide/topics/manifest/uses-sdk-element#ApiLevels) levels:

- Each API builds on previous versions in an additive way.
- Old APIs are deprecated but rarely removied.
- New Android versions are backward-compatible.
- Each device runs one Android framework version.
- Minimum API level: Each app needs to specify which versions it can work on.
- Target API level: For which the app was designed and tested (ideally, latest).

Android Manifest

- The most important file in an Android app. [docs](https://developer.android.com/guide/topics/manifest/manifest-intro)
- Key information needed by the framework to run the app.

Manifest Components:

- Activities
- Services
- Intent Filters
- Min / Target SDK
- Permissions [docs](https://developer.android.com/guide/topics/permissions/overview)

Android Studio (important paths):

- [android-studio]/bin/studio.sh
- ~/Android/Sdk/platforms-tools/{adb,fastboot}
- ~/Android/Sdk/build-tools/[version]/aap
- ~/.android/avd/\*
- ~/AndroidStudioProjects/[name]/app/build/outputs/apk/debug/app-debug.apk (If you don't find it: $ find -name "\*.apk")

## 4 - Intro to Android architecture and security

- Android is based on Linux.
- Every app has its own Linux user ID (they may share IDs using sharedUserId).
- Every app lives in its own security sandbox.

App installation

- Android framework creates a new linux user.
- Each app given a private directory (internal shared).

### Binder

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
               | Binder proxy  |  |   |  Binder stub   |
 User space    +---------------+  |   +----------------+
                                  |
+---------------------------------+------------------------+

 Kernel space           +--------------------+
                        |   Binder driver    |
                        +--------------------+

                        +--------------------+
                        |    Linux Kernel    |
                        +--------------------+

</pre>

Binder internals

- ```/dev/binder```
- ioctl syscall

Managers

```
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
- Steps (A calls B.X)
	1. A calls ```startActivity(new Intent(B.X))```
	2. Binder Driver calls privileged process ActivityManager.
	3. Activity Manager calls Binder Driver to call B.
	4. Activity B.X calls ```onCreate()```

### Android permission system [docs](https://developer.android.com/reference/android/Manifest.permission#SEND_SMS)

- Android framework has a long list of permissions.
- Example: ```android.permission.INTERNET```
- {READ,WRITE}_EXTERNAL_STORAGE: /sdcard (in the past removable)

```
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

RECEIVE_BOOT_COMPLETED

- System broadcasts "ACTION_BOOT_COMPLETED" on booting.
- An app can use intent-filters to automatically start at boot.
- Useful to gain persistence (but requires a permission).

SYSTEM_ALERT_WINDOW

- Draw on top of other apps.
- Custom posistion, shape, content transparency.
- Leads to attacks: UI confusion, clickjacking, phishing, [Cloak & Dagger](https://www.youtube.com/watch?v=RYQ1i03OVpI&t=1s).

Permission Protection Levels [docs](https://developer.android.com/guide/topics/permissions/overview#normal-dangerous)

- Normal: automatically grant permission at install time without user prompt (users can't revoke these permissions).
- Dangerous: prompt user to grant permission at run time.
- Signature: granted at install time if app signed by same certificate as app defining permission.
- Special: must include in manifest + send intent to user (Ex: SYSTEM\_ALERT_WINDOW, WRITE_SETTINGS).

Permission Granting

- Normal: nothing explicit
- Dangerous: user prompt (API &gt;= 23: runtime, API &lt; 23: install time)
- Signature: certificate or user prompt

Permissions Groups

- Example: SMS: RECEIVE\_SMS, READ\_SMS, SEND\_SMS
- Other mappinngs over [here](https://developer.android.com/guide/topics/permissions/overview#permission-groups).

```xml
    <uses-permission android:name="android.permission.SEND_SMS"/>
```

- Custom Permissions [docs](https://developer.android.com/guide/topics/permissions/defining)
- System Permissions defined in the same [way](http://androidxref.com/8.1.0_r33/xref/frameworks/base/core/res/AndroidManifest.xml#566).
- Components Permission Enforcement (for specific components within an app).

Permission Enforcement Implementation

- Ways: Linux groups vs. explicit checks
- [Groups](http://androidxref.com/8.1.0_r33/xref/frameworks/base/data/etc/platform.xml#24): INTERNET = inet, BLUETOOTH = be_net
- Checks: service's code does a check

android:exported [docs](https://developer.android.com/guide/topics/manifest/activity-element#exported)

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

android:shareUserId [docs](https://developer.android.com/guide/topics/manifest/manifest-element#uid)

- Apps can request to be assigned the same Linux user ID only if their certificates are the same.
- Both apps can access each others internal storage, components.

```android:shareUserId="com.mobisec.shareduser"```

Resources [docs](https://developer.android.com/guide/topics/resources/providing-resources)

- Additional files and static content that the app uses.
- drawable, layout, raw
- values: {arrays, colors, strings}

Resources under the hood

```
# smali code
const v4, 0x7f07002b

# res/values/strings.xml
\<string name="secret\_string"\>Juicy Secret\</string\>

# res/values/public.xml (it specifies the mapping)
\<public type="string" name="secret\_string" id="0x7f07002b" /\>

```

RunTime.exec() [docs](https://developer.android.com/reference/java/lang/Runtime)

- Analogous to C's system() or Python's os.system()
- Runtime.exec("cp ../flag /sdcard/leaked-flag.txt")

Reflection [docs](https://developer.android.com/reference/java/lang/reflect/package-summary)

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

```
Class<?> cls = (Class<?>) classloader.loadClass("com.mobisec.Peppa");
Method m = cls.getMethod("pig");
```

Serialization

- Serialized version of objects encode data about the objects, not the definition of the class.
- Objects need to be serialized before they are sent via Binder.
- Two main [interfaces](https://www.javacodegeeks.com/2014/01/android-tutorial-two-methods-of-passing-object-by-intent-serializableparcelable.html): [Parcelable](https://developer.android.com/reference/android/os/Parcelable), [Serializable](https://developer.android.com/reference/java/io/Serializable)


## 6 - More on Key Android Aspects

