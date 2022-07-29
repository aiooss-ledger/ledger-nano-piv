from smartcard.System import readers

def exchange_and_expect(input_hex: str, expected_output_hex: str):
    data, _sw1, _sw2 = connection.transmit(list(bytes.fromhex(input_hex)))
    assert bytes(data) == bytes.fromhex(expected_output_hex), f"{bytes(data)} != {bytes.fromhex(expected_output_hex)}"

r = readers()
connection = r[0].createConnection()
connection.connect()

exchange_and_expect('00a4040005a000000308', '61114f0600001000010079074f05a000000308')
#exchange_and_expect('00f8000000', '1234'.encode('utf-8').hex())
#exchange_and_expect('00fd000000', '050400')
#exchange_and_expect('00cb3fff055c035fc10d', '')
