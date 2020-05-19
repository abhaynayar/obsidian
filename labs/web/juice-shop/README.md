## OWASP - Juice Shop (Solutions)

### 1-star
#### Bonus Payload
- Copy and paste the payload into the search bar:

```html
<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>
```

#### Confidential Document
- `http://localhost:3000/#/about`
- `http://localhost:3000/ftp/legal.md`
- `http://localhost:3000/ftp/`
- `http://localhost:3000/ftp/acquisitions.md`

#### DOM XSS
Search for ` <iframe src="javascript:alert(`xss`)">`

#### Error Handling
In login page, enter `'` for username and password.

#### Exposed Metrics
From the prometheus docs `https://prometheus.io/docs/introduction/first_steps/` we can see that we need to go to `http://localhost:3000/metrics`

#### Missing Encoding
- `http://localhost:3000/#/photo-wall`
- The cat's photo isn't appearing.
- If you click the tweet button you see that text upto the first `#` is appearing, therefore we need to encode the `#` to `%23` so that the browser doesn't interpret it as a fragment.
- Change `http://localhost:3000/assets/public/images/uploads/%F0%9F%98%BC-#zatschi-#whoneedsfourlegs-1572600969477.jpg` to `http://localhost:3000/assets/public/images/uploads/%F0%9F%98%BC-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg`

### Outdated Whitelist

- Add an item to your basket and go to payment page.
- Go to sources tabs in your devtools.
- Search for `redirect` in `main-es2015.js`
- You'll find redirect URLs for pages not mentioned in the payment page such as `"./redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm"`.
- Simple visit the redirect URL to solve the challenge.

#### Privacy Policy
- Go to `http://localhost:3000/#/privacy-security/privacy-policy`

#### Repititive Registration
- Register for a user and intercept the requests in a proxy.
- Remove the `passwordRepeat` option in the json request.

#### Score Board
Go to `http://localhost:3000/#/score-board`

#### Zero Stars
- Go to customer feedback and intercept the request.
- Change the `rating` to 0 in the json payload.

### 2-star
#### Login Admin
- Use SQL injection in the login page `'or 1=1--`.

#### Admin Section
- Goto sources `main-es2015.js` and search for admin.
- You'll find references to `administration`.
- Once logged in as admin using SQL injection, go to: `localhost:3000/#/administration`

#### Five-Star Feedback
- Go to the `administration` section and delete any five feedbacks that are present.


