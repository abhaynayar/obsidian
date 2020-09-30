import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/js-4/?780929.71'
response = requests.get(url, cookies=cookies)

print(response.text)

