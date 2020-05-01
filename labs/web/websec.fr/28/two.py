import requests

url = 'http://websec.fr/level28/f3959b484667e8ab56a4e0cafba2b430.php'

while True:
    response = requests.get(url)
    if 'Not Found' in response.text:
        print('Not Found')
    else:
        print(response.text)
        break
