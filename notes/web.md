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

- Do a simple sanity check for `'` or `"` in payload. Try bypassing client side restrictions for input in fields such as date.
- Once you have a good working injection, move the work over to sqlmap. End sqlmap detection phase once it finds a positive.
- While `union` can be used with `select`, look for **stacked queries** to execute any SQL statement. Remember to commit.
- If any words are filtered, see if they are done recursively. If not, `selselectect` if will work.

#### PHP issues

- Type confusion: If an array is passed to `strcmp()`, it will give a warning but the compare result returns 0.
- Object injection: If `unserialize()` is being used, you might be able to craft an object and trampoline over `__destruct()`.

#### XSS
#### XXE
#### SSTI
#### SSRF
#### CSRF
