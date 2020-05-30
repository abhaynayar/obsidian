import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/code-5/index.php?hit=umg'

for i in range(100):
    response = requests.get(url, cookies=cookies)
    print(i)

