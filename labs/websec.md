# Portswigger's Web Security Academy

## Access Control

- **Authentication** identifies the user and confirms that they are who they say they are.
- **Session management** identifies which subsequent HTTP requests are being made by that same user.
- **Access control** determines whether the user is allowed to carry out the action that they are attempting to perform.

### User's perspective:

1. Vertical access controls
2. Horizontal access controls
3. Context-dependent access controls

### Parameter-based access control methods: hidden field, cookie, preset query string

```
lab: unprotected admin functionality => robots.txt
lab: unpredictable admin functionality => view source > js to check admin > /admin-uhsegl
lab: parameter based access control => login as wiener:peter > go to /admin
lab: modify user-role: parat
```

### Platform misconfiguration:
- restricting urls
- http methods
- *custom http headers to override restricted urls*
