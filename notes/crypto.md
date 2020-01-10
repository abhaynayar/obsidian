## ► crypto

### Learn
- Cryptopals: <https://cryptopals.com/>
- Crypton: <https://github.com/ashutosh1206/Crypton>

### Website
- [cryptograms](https://quipqiup.com/)
- [caesar cipher](http://rot13.com)

### Tools
- RsaCtfTool

### RSA
- if ```n``` is given, try checking if it is already factored at http://factordb.com
- use Crypto.Util.number inverse to find modular inverse for RSA
- use RsaCtfTool to perform known attacks against RSA

### AES
- use this tool to decrypt AES encrypted files: http://aes.online-domain-tools.com/
- or use python
```
from Crypto.Cipher import AES

obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
message = "The answer is no"
ciphertext = obj.encrypt(message)
'\xd6\x83\x8dd!VT\x92\xaa`A\x05\xe0\x9b\x8b\xf1'

obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
obj2.decrypt(ciphertext)
'The answer is no'
```
