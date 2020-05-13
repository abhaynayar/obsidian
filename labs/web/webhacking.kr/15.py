import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/js-2/?getFlag'
response = requests.get(url, cookies=cookies)

print(response.text)
