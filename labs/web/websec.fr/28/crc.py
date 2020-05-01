import binascii
import string
from itertools import chain, product

def bruteforce(charset, maxlength):
    return (''.join(candidate)
        for candidate in chain.from_iterable(product(charset, repeat=i)
        for i in range(1, maxlength + 1)))

for attempt in bruteforce(string.digits, 10):
    print(attempt)
    matched = (str(binascii.crc32(attempt.encode())) == attempt)
    if matched:
        break
