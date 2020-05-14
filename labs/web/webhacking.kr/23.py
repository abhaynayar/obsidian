import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/bonus-3/index.php?code='

# can't insert more than one alphabet
# can be inserted after with other characters in between

payload = '<h1>'

response = requests.get(url+payload, cookies=cookies)
if 'no hack' not in response.text:
    print(response.text)

