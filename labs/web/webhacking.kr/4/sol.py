import hashlib
import os

for i in range(23807095,99999999+1):
    m = str(i)+'salt_for_you'
    for j in range(500):
        m = hashlib.sha1(m.encode()).hexdigest()
    print(i,m)
    if m == '258c9b35267407e0cf4c4fba6421f96dcee6af91':
        duration = 1  # seconds
        freq = 440  # Hz
        os.system('play -nq -t alsa synth {} sine {}'.format(duration, freq))
        break
