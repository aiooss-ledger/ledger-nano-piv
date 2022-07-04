from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

from binascii import hexlify, unhexlify
from time import sleep

SPECULOS = True

if SPECULOS:
    d = getDongleTCP(port=9999)  # Speculos
else:
    d = getDongle()  # Nano

def exchange_and_expect(input_hex: str, expected_output_hex: str):
    print(f'\n-> {input_hex}')
    r = d.exchange(bytes.fromhex(input_hex))
    print(f'<- {r.hex()}')
    assert r.hex() == expected_output_hex.lower()

def test_get_serial():
    exchange_and_expect('e0f8000000', '312e322e')

def test_get_version():
    exchange_and_expect('e0fd000000', '050400')