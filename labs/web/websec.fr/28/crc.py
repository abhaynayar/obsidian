import string
import binascii
import itertools

print('running...')
for attempt in itertools.count():
    print(binascii.crc32(str(attempt).encode()), attempt)
    matched = (binascii.crc32(str(attempt).encode()) == attempt)
    break

