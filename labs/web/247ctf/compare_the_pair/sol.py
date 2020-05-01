import itertools
from hashlib import md5
import string

salt = 'f789bbc328a3d1a3'

flag = False

for i in itertools.count():
    to_hash = salt + str(i)
    then_hash = md5(to_hash.encode()).hexdigest()
    print(f'{to_hash} -> {then_hash}')
    if then_hash[:2] == '0e' and then_hash[2:].isnumeric():
        input()

# ...
# f789bbc328a3d1a3237701816 -> eac5caf7ed7c39299c49840754f882d4
# f789bbc328a3d1a3237701817 -> 4f743cac51ce63a5d51aab8cedf9a7ba
# f789bbc328a3d1a3237701818 -> 0e668271403484922599527929534016

