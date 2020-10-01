## 4 - Intro to Android Architecture and Security

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

