# Reverse Engineering

**This section is extremely interesting and densely packed with useful information. I recommend you to go look at the slides, as these notes are the things I found were the most important knowledge gaps for me.**

[Link](https://docs.google.com/presentation/d/1Ty_NSiOLRIr__RsmIwiNC47aixxcUtgfQrR_z6TjmPg)

### Two main approaches

Static Analysis: take the app, unpack it, check what's inside (don't run it).

Dynamic Analysis: get to know what's going on at run-time by running the app.
  
Dynamic Analysis Techniques

1. Debugging
2. Instrumentation

#### Usual workflow

**Key: learn when to switch between static and dynamic analysis**

```
             +-------------------------------------------+
             |                                           v
+------------+--------------+            +-----------------------------+
|                           |            |                             |
|     Static Analysis       |            |      Dynamic Analysis       |
|                           |            |                             |
+---------------------------+            +---------------+-------------+
             ^                                           |
             |                                           |
             +-------------------------------------------+
```

### Static Analysis

- AndroidManifest.xml
	- Entrypoints enumeration, tell us what to expect when we run it
- assets/, res/
	- Resources, strings, binary blobs, etc.
	- Suggestion: quickly check for weird things, but don't lose too much time
- classes.dex (classes2.dex, ...)
	- disassemble / decompile them
- libs/\*.so: native code 
- META-INF/\*

#### Generic workflow

1. Start from the (main) entry points and try to understand what's going on
2. It's normal to end up using strings + grep
3. Collect info for dynamic analysis: "How can I arrive to this point?"

#### Non-trivialities

- Encrypted strings / values
- Complex algorithms
- DexClassLoader (Find the loaded classes.dex and unpack it separately)
- Reflective calls


#### META-INF/*

- Files
	- MANIFEST.MF: hashes of all files inside the APK
	- CERT.SF: like MANIFEST.MMF, but signed with the RSA key
	- CERT.RSA: info about public key used to sign CERT.SF (DER format)

- Dump
	- ```$ openssl pkcs7 -in CERT.RSA -inform DER -print```

- Verify it
	- $ apksigner verify app-name.apk

#### System-apps

- "system" apps are apps signed with the same certificate as the the app with package name "android".
- ```/system/framework/framework-res.apk```
- this is the APK that defines all the "dangerous" permissions.

### Dynamic Analysis

#### Debugging

[Decompile into empty project](https://blog.netspi.com/attacking-android-applications-with-debuggers/)

#### Instrumentation

- Manual app modifications
- Frida framework
- XPosed framework
- Cuckoo Droid
- Joe Sandbox






















