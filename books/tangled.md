## The Tangled Web
Michał Zalewski

## It starts with a URL
### URL Structure

```scheme://login:password@address:port/path/to/resource?query_string#fragment```

#### Scheme

- Case-insensitive
- IANA's list of valid scheme names such as: `http:` and `ftp:`
- Common browsers and third-party apps have their own.
- Pseudo-urls such as: `data:` and `javascript:`

Distinguishing between fully qualified absolute and relative urls:
- In a compliant absolute URL, only `+,-,.` may appear before `:`
- However in practice, they ignore leading newlines and white-spaces.
- Internet Explorer ignores the entire nonprintable character range of ASCII codes 0x01 to 0x1F.
- Chrome additionally skips 0x00, the NUL character.
- Most implementations also ignore newlines and tabs in the middle of scheme names.

#### Indicator of a heirarchical url `//`

- If the string is missing, the format and function of the remainder of the URL is undefined for the purpose of that specification and must be treated as an opaque, scheme-specific value.
- Example: `mailto:user@example.com?subject=Hello+world`
- No spec on what to do when the scheme is known to be nonhierarchical but where a “//” prefix still appears, or vice versa.
- `http:example.com` in Firefox, Chrome and Safari is treated the same as `http://example.com/` when no fully qualified base URL context exists and as a relative reference to a directory named example.com when a valid base URL is available.
- `javascript://example.com/%0Aalert(1)` is interpreted as valid non-heirarchical pseudo-url and the alert will pop.
- `mailto://user@example.com` by the book, only works in IE but I tested it on Firefox and Chrome.

#### Credentials to Access the Resource

- This location can specify a username, and perhaps a password, that may be required to retrieve the data from the server.
- The method through which these credentials are exchanged is not specified as a part of the abstract URL syntax, and it is always protocol specific.
- For those protocols that do not support authentication, the behavior of a credential-bearing URL is simply undefined.
- When no credentials are supplied, the browser will attempt to fetch the resource anonymously. *
- Most browsers accept almost any characters, other than general URL section delimiters. *

#### Server Address

- case-insensitive DNS name (such as example.com)
- raw IPv4 address (such as 127.0.0.1)
- IPv6 address in square brackets (such as [0:0:0:0:0:0:0:1])

IP notations relaxation:

- http://127.0.0.1/
- http://0x7f.1/
- http://017700000001/

DNS names:

- Theoretically, DNS labels need to conform to a very narrow character set (specifically, alpha- numerics, “.”, and “-”, as defined in RFC 1035)

```
One fascinating behavior of the URL parsers in all of the mainstream browsers is their
willingness to treat the character “o” (ideographic full stop, Unicode point U+3002)
identically to a period in hostnames but not anywhere else in the URL. This is report-
edly because certain Chinese keyboard mappings make it much easier to type this symbol
than the expected 7-bit ASCII value.
```

#### Server Port

- Each scheme is associated with a default port on which servers for that protocol are customarily run (80 for HTTP, 21 for FTP, and so on), but the default can be overridden at the URL level. 
- An interesting and unintended side effect of this feature is that browsers can be tricked into sending attacker-supplied data to random network services that do not speak the protocol the browser expects them to.

#### Hierarchical File Path

- Specific resource to be retrieved.

#### Query String

- Non-heirarchical parameters sent to the resource on the path.
- Most people are familiar with `name1=value1&name2=value2...`
- But the RFC considers it as a blob and the finally recepient can use it as he sees fit unlike the path.

#### Fragment ID

- Similar to the query string but that provides optional instructions for the client application rather than the server.
- In fact, the value is not supposed to be sent to the server at all.
- In practice it is used for specifying the name of an anchor HTML element for in-document navigation.

### Reserved Characters

- Only reserved and unreserved characters in their intended capacity are formally allowed to appear in the URL as is, all else are percent encoded.
- Reserved Characters:
    - Disrupt the URL: `: / ? # [ ] @`
    - For other schemes: `! $ & ' ( ) * + , ; =`
- Unreserved characters: alphanumerics and `- . _ ~`

- All else are escaped: `/` will be encoded as %2F (uppercase is customary but not enforced).
- Unreserved characters allowed to appear in an unescaped form; they are not required to do so.
     http://example.com/
     http://%65xample.%63om/
     http://%65%78%61%6d%70%6c%65%2e%63%6f%6d/

- However, all browsers allow `^ { | }` to appear in URLs without escaping.
- Internet Explorer further permits `< > [backtick]`

### Handling of Non-US-ASCII Text

- UTF-8 required more bytes to encode high-bit characters.
- Servers would not be able to tell if that %B1 was supposed to mean “±”, “a”, or some other character specific to the user’s native script.
- Most browsers internally transcode URL path segments to UTF-8.
- The traditional percent-encoding approach left just one URL segment.
- The well-established DNS standard permitted only period-delimited alphanumerics and dashes to appear in domain names
- Therefore [IDNA](https://en.wikipedia.org/wiki/Internationalized_domain_name) introduced punycode (which was problematic):
```
Intent: http://www.r ę czniki.pl/r ę cznik?model=Ja ś #Złóż_zamówienie
Actual URL: http://www.xn--rczniki-98a.pl/r%C4%99cznik?model=Ja%B6 #Złóż_zamówienie
```

### Common URL Schemes and Their Function

- Browser-supported, document-fetching: `http, https, ftp, file, gopher, shttp`
- Third-party and plugins: `mailto, firefoxurl, cf`
- Nonencapsulating pseudo-protocols: `javascript, data`

```
data:text/plain,Why,%20hello%20there!
data:text/html,<script>alert(document.location)</script>
```
- Encapsulating pseudo-protocols: `view-source, jar, wyciwyg, view-cache`

### Resolution of relative URLs

- `http:foo.txt`: copy {authority}, new {protocol, path, query, fragment}
- `//example.com`: copy {scheme}, new {all-else}
- `../notes`: copy {protocol, authority}, conditional {path}, new {query, fragment}
- `?search=asdf`: copy {protocol, authority, path}, new {query, fragment}
- `#asdf`: copy{everything}, new{fragment}

## HTTP
`TBD`

