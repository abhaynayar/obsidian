# frontdoor

After decompiling the app, we see that it is making a simple GET request to a URL for obtaining the flag.

It requires the INTERNET permission in the manifest:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.mobihac.frontdoor">

    <uses-permission android:name="android.permission.INTERNET"/>

    <application
        android:usesCleartextTraffic="true"
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">

        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

    </application>
</manifest>
```

Rest of the Java code was mostly the same as the decompiled output, with some fixes as and when errors presented themselves.

```java
package com.mobihac.frontdoor;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.os.StrictMode;
import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class MainActivity extends AppCompatActivity {

    private static boolean debug = true;
    private static String sUrl = "http://10.0.2.2:31337/getflag";

    public static String getFlag(String username, String password) throws Exception {

        String urlParameters;
        if (debug) urlParameters = "username=testuser&password=passtestuser123";
        else urlParameters = "username=" + username + "&password=" + password;

        int postDataLength = urlParameters.getBytes(StandardCharsets.UTF_8).length;
        HttpURLConnection conn = (HttpURLConnection) new URL(sUrl + "?" + urlParameters).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("charset", "utf-8");
        conn.setRequestProperty("Content-Length", Integer.toString(postDataLength));
        conn.setUseCaches(false);

        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String content = BuildConfig.FLAVOR;

        while (true) {
            String readLine = rd.readLine();
            String line = readLine;
            if (readLine == null) {
                return content;
            }
            content = content + line + "\n";
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        try {
            Log.e("MOBISEC", getFlag("who", "cares"));
        } catch (Exception e) {
            Log.e("MOBISEC", e.toString());
        }
    }
}
```

The flag can be found in the logs of the submission platform: ```MOBISEC{noob_hackers_only_check_for_backdoors}```

