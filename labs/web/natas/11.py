import requests
import re


url = 'http://natas11.natas.labs.overthewire.org/index-source.html'
auth = requests.auth.HTTPBasicAuth('natas11','U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK')
response = requests.post(url, auth=auth)
print(response.text)

# password = re.findall('(.*)', response.text)
# print(password[41]) # U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK

