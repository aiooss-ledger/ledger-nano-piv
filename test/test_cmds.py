from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

SPECULOS = True

if SPECULOS:
    d = getDongleTCP(port=9999)  # Speculos
else:
    d = getDongle()  # Nano


def exchange_and_expect(input_hex: str, expected_output_hex: str):
    print(f"\n-> {input_hex}")
    r = d.exchange(bytes.fromhex(input_hex))
    print(f"<- {r.hex()}")
    assert r.hex() == expected_output_hex.lower()


def test_select_card():
    exchange_and_expect("00a4040009a00000030800001000", "61114f0600001000010079074f05a00000030800001000")


def test_get_serial():
    exchange_and_expect("00f8000000", b"1234".hex())


def test_get_version():
    exchange_and_expect("00fd000000", "050400")


def test_get_key_history():
    exchange_and_expect("00cb3fff055c035FC10C", "5308c10101c20100fe00")


def test_get_chuid():
    expected = bytes([0x53, 59,
    0x30, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x34, 0x10, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x35, 0x08, 0x32,
    0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,]).hex()

    exchange_and_expect("00cb3fff055c035FC102", expected)

def test_get_ccc():
    expected = bytes([0x53, 51,
    0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf1, 0x01, 0x00, 0xf2, 0x01, 0x00, 0xf3, 0x00, 0xf4,
    0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd,
    0x00, 0xfe, 0x00,
    ]).hex()

    exchange_and_expect("00cb3fff055c035FC107", expected)


def test_get_retired_certificate():
    expected = bytes([0x53, 0x82, 0x01, 0xbf, 0x70, 0x82, 0x01, 0xb6, 0x30, 0x82, 0x01, 0xb2, 0x30, 0x82, 0x01, 0x59,
    0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x15, 0x00, 0x8d, 0x95, 0xd0, 0xad, 0x81, 0x07, 0x54, 0x1c,
    0x1f, 0x97, 0x37, 0x99, 0x8d, 0x4e, 0x00, 0x3e, 0x99, 0xc3, 0x77, 0x0c, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x4d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x12, 0x61, 0x67, 0x65, 0x2d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2d,
    0x79, 0x75, 0x62, 0x69, 0x6b, 0x65, 0x79, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0b,
    0x0c, 0x05, 0x30, 0x2e, 0x33, 0x2e, 0x30, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x15, 0x61, 0x67, 0x65, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20, 0x39,
    0x39, 0x35, 0x30, 0x65, 0x63, 0x65, 0x33, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x37, 0x30,
    0x34, 0x31, 0x34, 0x32, 0x33, 0x33, 0x34, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32,
    0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x4d, 0x31, 0x1b, 0x30, 0x19, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x12, 0x61, 0x67, 0x65, 0x2d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e,
    0x2d, 0x79, 0x75, 0x62, 0x69, 0x6b, 0x65, 0x79, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x05, 0x30, 0x2e, 0x33, 0x2e, 0x30, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x15, 0x61, 0x67, 0x65, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20,
    0x39, 0x39, 0x35, 0x30, 0x65, 0x63, 0x65, 0x33, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0x90, 0xf0, 0x3d, 0x92, 0xb3, 0xa9, 0xf7, 0x0d, 0x2c, 0x1e, 0x01, 0x96, 0x26,
    0x68, 0x99, 0x1f, 0x33, 0xa8, 0x22, 0x9f, 0x46, 0x3d, 0xb1, 0x9a, 0xb7, 0x92, 0xca, 0x0e, 0x5d,
    0x2a, 0x4e, 0x59, 0x13, 0x31, 0x75, 0x3b, 0x33, 0x02, 0x3d, 0x40, 0xa2, 0x9d, 0x2c, 0x4f, 0x6a,
    0x4a, 0x8d, 0x81, 0x82, 0xae, 0x69, 0xd1, 0xe7, 0x07, 0x0d, 0xae, 0xcd, 0xdb, 0xc8, 0xd2, 0x86,
    0x93, 0x1f, 0x4c, 0xa3, 0x14, 0x30, 0x12, 0x30, 0x10, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
    0x82, 0xc4, 0x0a, 0x03, 0x08, 0x04, 0x02, 0x01, 0x02, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x43, 0x9a, 0xf5, 0x07,
    0x33, 0x4b, 0xfe, 0x58, 0xb0, 0x8c, 0xb0, 0xd4, 0xca, 0x38, 0x54, 0x22, 0x90, 0x47, 0xdc, 0x1e,
    0x2c, 0x8d, 0xf4, 0x7a, 0x0d, 0x98, 0xe0, 0x67, 0x64, 0x17, 0x92, 0xcc, 0x02, 0x20, 0x5e, 0x37,
    0x06, 0x01, 0x61, 0xb2, 0x14, 0xef, 0x47, 0x32, 0x7c, 0x6c, 0x8c, 0x74, 0x1c, 0xad, 0x7f, 0xd5,
    0xc4, 0xfe, 0xd6, 0x57, 0xb4, 0x75, 0xdc, 0x9a, 0x46, 0x79, 0x0d, 0x37, 0x7a, 0x51, 0x71, 0x01,
    0x00, 0xfe, 0x00]).hex()

    exchange_and_expect("00cb3fff055c035fc10d", expected)
