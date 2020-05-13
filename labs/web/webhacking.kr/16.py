import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/js-3/%7C.php'
response = requests.get(url,cookies=cookies)

print(response.text)

