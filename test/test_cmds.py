from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

from binascii import hexlify, unhexlify
from time import sleep

SPECULOS = True

CMDS = []

if SPECULOS:
    d = getDongleTCP(port=9999)  # Speculos
else:
    d = getDongle()  # Nano

for cmd in map(unhexlify, CMDS):
    r = None
    try:
        r = d.exchange(cmd, 20)
        sleep(1)
    except Exception as e:
        print(e)
    if r is not None:
        print("Response : ", hexlify(r))
