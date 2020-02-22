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

Intents

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
- ~/AndroidStudioProjects/[name]/app/build/outputs/apk/debug/app-debug.apk

If you don't find it: $ find -name "\*.apk"
 


