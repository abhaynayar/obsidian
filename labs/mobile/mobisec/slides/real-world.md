## 5 - Real-World Android apps

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

