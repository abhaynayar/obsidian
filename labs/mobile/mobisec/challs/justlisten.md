# justlisten

> The flag is announced on the system with a broadcast intent with action com.mobisec.intent.action.FLAG\_ANNOUNCEMENT. The flag is in the Intent's bundle, under the "flag" key.

So we need to find how to create a broadcast receiver, and log the intent bundle "flag" after we receive it.

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

So we need to learn how to handle it from API >= 26.

----

In the newer versions of Android, we need to use something called
context-registered receivers. Here is the code I used to get the flag:

MainActivity.java

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        BroadcastReceiver br = new MyBroadcastReceiver();

        IntentFilter filter = new IntentFilter();
        filter.addAction("com.mobisec.intent.action.FLAG_ANNOUNCEMENT");
        this.registerReceiver(br, filter);
    }
}
```

MyBroadcastReceiver.java

```java
public class MyBroadcastReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Log.e("MOBISEC", intent.getStringExtra("flag"));
    }
}
```
