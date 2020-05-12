##  ► web
### Resources:

Courses

- [Web Security Academy](https://portswigger.net/web-security)
- [Pentesterlab](https://pentesterlab.com/)
- [OWASP-wstg](https://owasp.org/www-project-web-security-testing-guide/)
- [Hacker101](https://www.hackerone.com/hacker101)

CTF

- [247/CTF](https://247ctf.com/)
- [websec.fr](http://websec.fr/)
- [webhacking.kr](https://webhacking.kr/)
- [CTF Challenge](https://ctfchallenge.co.uk/)
- [Hacker101 CTF](https://ctf.hacker101.com/)
- [Google XSS Game](https://xss-game.appspot.com/)
- [Natas - OverTheWire](https://overthewire.org/wargames/natas/)
- [pwnfunction XSS Game](https://xss.pwnfunction.com/)

Vulnerable Apps

- [Vulhub](https://github.com/vulhub/vulhub)
- [DVWA](http://www.dvwa.co.uk/)
- [bWAPP](http://www.itsecgames.com/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

Bug Bounty

- [Web Hacking 101](https://leanpub.com/web-hacking-101)
- [Real World Bug Hunting](https://www.amazon.in/Real-World-Bug-Hunting-Field-Hacking-ebook/dp/B072SQZ2LG)
- [Resources for Beginner Bug Bounty Hunters](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/)
- [Intigriti Article](https://kb.intigriti.com/en/articles/3471127-useful-resources-about-web-hacking-bug-bounty)

### Tips

- Test things under different environments, browsers.
- Make a flow diagram of deciding to opt-in or out of features.
- Test every input, make sure to disregard any client-side restrictions.
- When one directory isn't accessible, try its subdirectories.
- In python `requests` there is url-encodint is done automatically.
- Look into the URI spec `https://www.ietf.org/rfc/rfc3986.txt`.
- If certain characters are blocked, use illegal unicode chars in Burp Intruder.
- For faster HTTP requests and multithreading use `Turbo Intruder`.
- Sometimes, `Wappalyzer` may detect extra information in view-source.
- Be aware of encodings. For example, browsers automatically URL-encode certain things.

### Tools

<table>
<thead>
<tr><th>Tools</th>
<th>Usage</th></tr>
</thead>
<tbody>

<tr>
<td>ffuf</td>
<td>$ ffuf -w ~/wordlists/common.txt -u https://example.com/FUZZ<br>
$ ffuf -w ~/wordlists/10-million-password-list-top-100.txt -X POST -d "username=admin&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u https://www.example.com/login -mc all -fc 200<br>
$ ffuf -w ~/wordlists/common.txt -b "cookie1=value1;cookie2=value2" -H "X-Header: ASDF" -u https://example.com/dir/FUZZ</td>
</tr>

<tr>
<td>sublist3r</td>
<td>$ sublister -d example.com</td>
</tr> 

<tr>
<td>dnsrecon</td>
<td>$ dnsrecon -n 8.8.8.8 -d example.com<br>
$ dnsrecon -d example.com -D ~/wordlists/namelist.txt -t brt</td>
</tr>

<tr>
<td>gau</td>
<td>$ echo example.com | gau<br>
$ cat domains.txt | gau</td>
</tr>

<tr>
<td>paramspider</td>
<td>$ python3 paramspider.py --domain hackerone.com</td>
</tr>

<tr>
<td>turbointruder</td>
<td>https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack</td>
</tr>

</tbody>
</table>


### Vulnerability Classes
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

- [Portswigger - Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)
- For time-based, first figure out the max time a request can take.
- For faster blind-sqli execution, first check what characters `*i*` does the target string contain from `string.printable` and append it to a filtered list. Then from that filtered list of characters, check the real order of the target string `i*`.
- Remember to start `substring(str,pos,len)` from `1` not `0`.
- Use `LIKE BINARY` for case-senstivie blind sqli matching.
- For postgres time-based, `||pg_sleep(10)`
- For postgres time-based conditions `'; SELECT CASE WHEN (condition) THEN pg_sleep(10) ELSE pg_sleep(0) END--`

#### PHP issues

- Sometimes `<?` does not work but `<?php` does.
- Type confusion: If an array is passed to `strcmp()`, it will give a warning but the compare result returns 0.
- Object injection: If `unserialize()` is being used, you might be able to craft an object and use trampoline functions.
- Type juggling: `0e123` evaluates to `0`.

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
    - Retrieve files
    - SSRF through XXE

#### CSRF
- Try removing the anti-CSRF token altogether.
- Try submitting anti-CSRF token generated for one user in another user's session.
- Submitting forms through JavaScript: `document.getElementById("myForm").submit();` or `document.forms[0].submit();`

#### Command Injection

- Try `|ls`.
- For time delays use `sleep 10` or `& ping -c 10 127.0.0.1 &`
- Redirect output to a file you can read using your browser.

