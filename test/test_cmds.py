from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

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

def test_select_card():
    exchange_and_expect('00a4040005a000000308', '61114f0600001000010079074f05a000000308')

def test_get_serial():
    exchange_and_expect('00f8000000', '1234'.encode('utf-8').hex())

def test_get_version():
    exchange_and_expect('00fd000000', '050400')
