# vulnltd.co.uk

## Flag1
- Robots.txt: `[^FLAG^B14F856BC5AD17151A55F097E1805A01^FLAG^]`
- Also found: `/secr3t_l0g1n/`,  ffuf => `login,logout,docs`

## Flag2

- In `/secr3t_l0g1n/` redirected to `/login`.
- Using hint from `/docs`:

```bash
$ ffuf -w day_of_week.txt -X POST -d "username=guest&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -u https://www.vulnltd.co.uk/secr3t_l0g1n/login -mc all`
tuesday                 [Status: 302, Size: 0, Words: 1, Lines: 1]
```

- Login as guest and set cookie "admin=true" `[^FLAG^F01EF758672F38E8C7BF41B0AD1BB431^FLAG^]`

## Flag3
> Hint: Maybe your next step isn't a website request.

- Since we can't modify or create web pages, maybe we are supposed to extract information from the CMS?
- Found: `https://support.vulnltd.co.uk/` => can supply support ticket ref.

