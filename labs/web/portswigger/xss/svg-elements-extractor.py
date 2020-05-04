import requests
import re

response = requests.get('https://developer.mozilla.org/en-US/docs/Web/SVG/Element')
tags = re.findall('<a.*><code>&lt;(.*)&gt;</code></a>', response.text)

unique = list(dict.fromkeys(tags))

for x in unique:
    print (x)

