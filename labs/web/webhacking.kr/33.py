import requests
import hashlib
import time

from phpsessid import cookies

url = 'https://webhacking.kr/challenge/bonus-6/'
query = '?get=hehe'

# response = requests.get(url+query)
# print(response.text)

# data = {'post':'hehe', 'post2':'hehe2'}
# response = requests.post(url+'lv2.php', data=data)
# print(response.text)


# query = '?myip=103.41.24.37'
# response = requests.get(url+'33.php'+query)
# print(response.text)

# query = '?password=' + hashlib.md5(str(int(time.time())+2).encode()).hexdigest()
# response = requests.get(url+'l4.php'+query)
# print(response.text)

# query = '?imget=hi'
# data = {'impost':'hi'}
# cookies['imcookie'] = 'hi'

# response = requests.post(url+'md555.php'+query, cookies=cookies, data=data)
# print(response.text)

# cookies['test'] = hashlib.md5(b'103.41.24.37').hexdigest()
# data = {'kk': hashlib.md5(b'python-requests/2.23.0').hexdigest()}
# response = requests.post(url+'gpcc.php', cookies=cookies, data=data)
# print(response.text)

# query = '?103412437=103412437'
# response = requests.get(url+'wtff.php'+query)
# print(response.text)

# query = '?addr=127.0.0.1'
# response = requests.get(url+'ipt.php'+query)
# print(response.text)

# query = '?ans=acegikmoqsuwy'
# response = requests.get(url+'nextt.php'+query)
# print(response.text)

# response = requests.get(url+'forfor.php')
# print(response.text)

# look into ./33.php
response = requests.get(url+'answerip/2755377553_5510755106.php', cookies=cookies)
print(response.text)

