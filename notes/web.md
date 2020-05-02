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
- Test every input, but know when to give up.
- When one directory isn't accessible, try its subdirectories.
- Chrome, Firefox, Safari encode `location.search` and `location.hash`.
- IE11 and Edge (pre-Chromium) don't encode sources.

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

#### PHP issues

- Type confusion: If an array is passed to `strcmp()`, it will give a warning but the compare result returns 0.
- Object injection: If `unserialize()` is being used, you might be able to craft an object and use trampoline functions.
- Type juggling: `0e123` evaluates to `0`.

#### XSS

- [Portswigger - XSS cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [Portswigger - XSS contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- When browsers parse tag attributes, they HTML-decode their values first. `<foo bar='z'>` is the same as `<foo bar='&#x7a;'>`
- AngularJS `ng-app` attribute is processed by AngularJS. Anything within `{{}}` will be executed.
- jQuery `attr()` used to change attributes, can act as a sink.

#### XXE

- [PayloadAllTheThings - XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)
    - Retrieve files
    - SSRF through XXE

#### SSTI
#### SSRF
#### CSRF

