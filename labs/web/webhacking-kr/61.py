import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/web-38/?id='
query = ''

if len(query)>15:
    print('error: len(query)>15')
    exit()

response = requests.get(url+query, cookies=cookies)
print(response.text)

