import struct

d = []
d.append(struct.pack('II',10,10))
d.append(b'A' * 10*10)
open('input.sample','wb').write(b''.join(d))

