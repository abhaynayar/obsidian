# MOBISEC

> Prof. Yanick Fratonio
> [https://mobisec.reyammer.io/](https://mobisec.reyammer.io/)

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
- [Access to GPS/location](https://developer.android.com/reference/android/location/LocationManager.html#requestLocationUpdates(java.lang.String,%20long,%20float,%20android.location.LocationListener)

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


