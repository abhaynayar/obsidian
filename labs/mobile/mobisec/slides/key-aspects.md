## 6 - More on Key Android Aspects

Activity

- startActivity(intent)
- New: activities can also get an answer / result.

```java
# A.X

Intent i = new Intent(...);
int requestCode = 400;
startActivityForResult(i, requestCode);

# B.Y

onCreate() {
  Intent resInt = new Intent();
  ...
  setResult(Activity.RESULT_OK, resInt);
  finish();
}

# don't know what this means

onActivityResult(int requestCode, int resultCode, Intent data) {
  // check requestCode and resultCode
  ...
}

```

Service

- No analogous startActivityForResult(), but can use broadcast intents.
- To start a service:

```java

// Intent must be explicit (not required for activities since they have a chooser dialog)
Intent i = new Intent(...);

startService(i)

```

Types of Services [~](https://developer.android.com/guide/components/services)

- Background ```startService() → S.onCreate() → S.onStartCommand()```
- Foreground ```startService() + startForeground() → S.onCreate() → S.onStartCommand()```
- [Bound](https://developer.android.com/guide/components/bound-services) ```bindService() → S.onCreate() → S.onBind()```


Three ways of implementing:

1. Local service (intra-app)
2. Using a messenger.
3. Using AIDL.

Inter-Process Services via Messengers [~](https://developer.android.com/guide/components/bound-services)

```java
public IBinder onBind(Intent intent) {
    mMessenger = new Messenger(new IncomingHandler(this));
    return mMessenger.getBinder();
}

static class IncomingHandler extends Handler {
    IncomingHandler(Context context) { ... }

    @Override
    public void handleMessage(Message msg) {
        switch (msg.what) {
             case MSG_SAY_HELLO:
            ...
		}
	}	
}

private ServiceConnection mConnection = new ServiceConnection() {
  public void onServiceConnected(ComponentName className, IBinder service) {
    mService = new Messenger(service);
    mBound = true;
  }
  ...
};

bindService(new Intent(...), mConnection, Context.BIND_AUTO_CREATE);

Message msg = Message.obtain(null, MessengerService.MSG_SAY_HELLO, 0, 0);
mService.send(msg);
```

Broadcast Intent and Receivers

- sendBroadcast(intent);
- Relevant broadcast receivers will be woken up.
- Register via manifest and intent-filter or at run-time (only for broadcast receivers).

```java
MyReceiver customRec = new MyReceiver();
IntentFilter intFil = new IntentFilter("com.some.action");
registerReceiver(customRec, intFil);
```

Bundles

- Pass data around via intents.
- Wrapper around key-value store.
- key: String, value: any serializable class

```java
bundle.putString("flag", "hereismyflag");
bundle.putInt("num", 42)
```

```java
intent.putExtra("flag", "flagvalue");
intent.putExtra("num", 42);

intent.getExtras() ~> Bundle object
```

PackageManager

```
PackageManager pm = context.getPackageManager();
List<ResolveInfo> list = pm.queryIntentServices(implicitIntent, 0);
ResolveInfo serviceInfo = list.get(0); // if any
ComponentName component = new ComponentName(
   serviceInfo.serviceInfo.packageName,
   serviceInfo.serviceInfo.name);
```

