import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/js-1/?291600'
response = requests.get(url, cookies=cookies)

print(response.text)

