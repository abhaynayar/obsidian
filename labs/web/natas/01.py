import requests
import re

url = 'http://natas1.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas1', 'gtVrDuiDfck831PqWsLEZy5gyDz1clto')
response = requests.get(url, auth=auth)
password = re.findall('<!--The password for natas2 is (.*) -->', response.text)
print(password[0]) # ZluruAthQk7Q2MqmDeTiUij2ZvWy2mB

