# ► crypto
## Learn

- Crypton: https://github.com/ashutosh1206/Crypton
- Cryptohack: https://cryptohack.org/
- Cryptopals: https://cryptopals.com/

## Websites

- [ciphers](https://www.dcode.fr)
- [cyber chef](https://gchq.github.io/CyberChef/)
- [cryptograms](https://quipqiup.com/)
- [caesar cipher](http://rot13.com)
- [vignere cipher](https://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx)

## RSA

- If `n` is given, try checking if it is already factored at
  http://factordb.com
- Use Crypto.Util.number inverse to find modular inverse for RSA
- Use RsaCtfTool to perform known attacks against RSA

## AES

- Use this tool to decrypt AES encrypted files: http://aes.online-domain-tools.com/
- Or use python

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

## Hacker101
### Crypto Crash Course

XOR has a property that makes it important for crypto:

```
If   D = A^B
Then A = D^B
And  B = D^A
```

So we can produce a cryptographic scheme as follows:

1. Generate a Key of N random bits
2. Plaintext ^ Key = Ciphertext
3. Ciphertext ^ Key = Plaintext

This is called one-time pad (OTP) and it has its limitations.


Types of Ciphers:

1. Symmetric: both sides share the same key
  1. Stream: data encrypted byte-wise
  2. Block: data encrypted block-wise
2. Asymmetric: both sides has pair of keys

Stream Ciphers:

- RC4: used in SSL.
- Operation similar to OTP above.
- Encryption and decryption operation is the same (XOR).
- Seeded key on both sides used on chosen PRNG (pseudorandom number
  generator).
- Strength of algorithm relies solely on the quality of the randomness.

Block Ciphers:

- AES (Rjindael), DES, 3DES, Twofish.
- Split data into N-byte blocks and encrypt them separately.
- Since data can't always be a multiple of N-bytes, we use padding.
- Due to padding complexity increases and encryption and decryption aren't the same anymore.
- Mode:
	- Electornic Codebook: each block encrypted independently to produce a ciphertext block.
	- Cipher-Block Chaining: each block XORed with ciphertext of previous block (first block with IV).

Asymmetric Ciphers:

- RSA
- Used for both encryption and signing.
- Generally not used to encrypt data, due to complexity.
- Rather used to securely transmit keys.

Hashes:

- Take in an arbritrary blob of data and generate a fixed size output.
- Since we have infinite number of inputs, there may be output collisions.
- Strength of hash algorithm is how hard it is to find such collisions.
- Hashes used for checking the integrity of data.

MAC:

- Message Authentication Codes are generally based on hashes.
- With a MAC you have a shared key used to create a valid MAC.

HMAC:

- Most well-known MAC is HMAC.
- HMAC(key, msg) = hash(key + hash(key+msg))
- Keys are padded in each run of the hash algorithm.
- What does "+" in the above formula mean? Concatenation?

Crypto Attacks:

Stream Cipher Reuse:

```
A ^ C = A'
B ^ C = B'

A' ^ B' = (A^C) ^ (B^C)
A' ^ B' = A ^ B

# Thus, if we have encrypted text B'
# We can generate A and A' to get B
```

- This is not prevalent in modern stream ciphers.
- Nonce along with key in eSTREAM.
- As long as you don't reuse given key-nonce pair.
- However it is still prevalent in RC4.
- Therefore RC4 needs to be XORed with a nonce prior to encryption or
  decryption.

ECB Block Reordering:

- DES uses 8 byte blocks.
- These block can be reordered.
