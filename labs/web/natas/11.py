import itertools
import requests
import base64
import re

json = '{"showpassword":"yes","bgcolor":"#ffffff"}'
data = 'ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw='
b64d = base64.b64decode(data)

key = ''
for i,j in zip(b64d[:4], json[:4]):
    key += chr(i^ord(j))

def xor(data, key):
    return ''.join(chr(x^y) for (x,y) in zip(data.encode(), itertools.cycle(key.encode())))
data = base64.b64encode(xor(json,key).encode())
cookies = {'data':data.decode()}

url = 'http://natas11.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas11','U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK')
response = requests.get(url, auth=auth, cookies=cookies)
password = re.findall('The password for natas12 is (.*)<br>', response.text)
print(password[0]) # EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3

