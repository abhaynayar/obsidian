# Injured Android Write-up

## Setup

Just clone the repository to your local machine.  
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

For exported activities, we need to look into the manifest.

We see that the following activity is exported:

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

We simple need to base64 decode the given string:

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

Looking at the code of the latter, we see that once the receiver is called twice, we get the flag.

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

We see that we need to reverse a custom decrypt method implemented in the `VGV4dEVuY3J5cHRpb25Ud28` class. But since we already have a pretty good decompiled version of the Java code, we simply need to copy and paste the code to an external file and run the Java code after doing some necessary fixes.

```bash
$ javac VGV4dEVuY3J5cHRpb25Ud28.java 
$ java VGV4dEVuY3J5cHRpb25Ud28 
Decrypted: k3FElEG9lnoWbOateGhj5pX6QsXRNJKh///8Jxi8KXW7iDpk2xRxhQ== -> {This_Isn't_Where_I_Parked_My_Car}
```

## Flag Seven - SQLite


