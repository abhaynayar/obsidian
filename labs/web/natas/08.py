import requests
import base64
import re

url = 'http://natas8.natas.labs.overthewire.org/index-source.html'
auth = requests.auth.HTTPBasicAuth('natas8','DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe')
response = requests.get(url, auth=auth)

encodedSecret = re.findall('encodedSecret&nbsp;=&nbsp;"(.*)";<br /><br />function&nbsp;encodeSecret', response.text)[0]
ascii_string = bytes.fromhex(encodedSecret).decode('ASCII')
decodedSecret = base64.b64decode(ascii_string[::-1])

url = 'http://natas8.natas.labs.overthewire.org/'
response = requests.post(url, auth=auth, data={'submit':'submit', 'secret':decodedSecret})
password = re.findall('Access granted. The password for natas9 is (.*)', response.text)
print(password[0]) # W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl

