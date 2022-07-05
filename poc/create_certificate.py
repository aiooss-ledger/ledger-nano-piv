#!/usr/bin/env python3
"""Create a cert with a given private key"""
import struct
import subprocess

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate

from decode_get_data import decode_getdata_response

# TODO
my_private_key = 42

certificate_template = bytes.fromhex("""
    308201b230820159
    a0030201020215008d95d0ad8107541c
    1f9737998d4e003e99c3770c300a0608
    2a8648ce3d040302304d311b30190603
    55040a0c126167652d706c7567696e2d
    797562696b6579310e300c060355040b
    0c05302e332e30311e301c0603550403
    0c15616765206964656e746974792039
    393530656365333020170d3232303730
    343134323333345a180f393939393132
    33313233353935395a304d311b301906
    0355040a0c126167652d706c7567696e
    2d797562696b6579310e300c06035504
    0b0c05302e332e30311e301c06035504
    030c15616765206964656e7469747920
    39393530656365333059301306072a86

    48ce3d020106082a8648ce3d03010703
    420004a8df593332d7e1689558a6d997
    9922a692054591dfc66f34cb62446ae9
    2aa0d7c2cb755b2da012dbcdf1dde9d2
    f3a7a10c84fc7d8232d0b2e1213a1146
    5fe955a31430123010060a2b06010401
    82c40a030804020102300a06082a8648
    ce3d040302034700304402207fc3cf40
    8e1918671bb2b3bbec7a8c96382db2c1
    a019c413e98f652cddfa8a9c02205e6d
    4d1571e8693d23ca9638a794f0aa5c94
    8958658f0b3b2ed9744894a9b32f
""")

# subprocess.run(("openssl", "asn1parse", "-inform", "DER", "-i", "-dump"), input=certificate_template)

pubkey_offset = certificate_template.index(bytes.fromhex("04a8df593332d7e1689558a6d997"))
pubkey_size = 0x41
signature_offset = certificate_template.index(bytes.fromhex("304402207fc3cf40"))
signature_size = 0x46
tbs_cert_offset = 4
tbs_cert_size = 0x15d

# Verify the offsets in the template
test_cert_template = load_der_x509_certificate(certificate_template)
assert len(test_cert_template.signature) == signature_size
assert test_cert_template.signature == certificate_template[signature_offset:signature_offset + signature_size]
test_pubkey_bytes = test_cert_template.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
assert len(test_pubkey_bytes) == pubkey_size
assert test_pubkey_bytes == certificate_template[pubkey_offset:pubkey_offset + pubkey_size]

assert len(test_cert_template.tbs_certificate_bytes) == tbs_cert_size
assert test_cert_template.tbs_certificate_bytes == certificate_template[tbs_cert_offset:tbs_cert_offset + tbs_cert_size]

# Verify the signature of the template certificate
test_cert_template.public_key().verify(
    test_cert_template.signature, test_cert_template.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))

# Create a certificate
curve = ec.SECP256R1()
my_key = ec.derive_private_key(my_private_key, curve)
assert my_key.private_numbers().private_value == my_private_key

my_pubkey_bytes = my_key.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
assert len(my_pubkey_bytes) == pubkey_size

my_cert = bytearray(certificate_template)
my_cert[pubkey_offset:pubkey_offset + pubkey_size] = my_pubkey_bytes
my_signature = my_key.sign(my_cert[tbs_cert_offset:tbs_cert_offset + tbs_cert_size], ec.ECDSA(hashes.SHA256()))
# assert len(my_signature) == signature_size
assert signature_offset + signature_size == len(my_cert)
my_cert = my_cert[:signature_offset] + bytearray(my_signature)
assert bytes(my_cert[signature_offset - 3:signature_offset]) == bytes.fromhex("034700")
my_cert[signature_offset - 2] = len(my_signature) + 1
my_cert[2:4] = struct.pack(">H", 0x01b2 - signature_size + len(my_signature))

# Check the certif
test_cert = load_der_x509_certificate(my_cert)
assert len(test_cert.signature) == len(my_signature)
assert test_cert.signature == my_cert[signature_offset:signature_offset + len(my_signature)]
test_pubkey_bytes = test_cert.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
assert len(test_pubkey_bytes) == pubkey_size
assert test_pubkey_bytes == my_cert[pubkey_offset:pubkey_offset + pubkey_size]

assert len(test_cert.tbs_certificate_bytes) == tbs_cert_size
assert test_cert.tbs_certificate_bytes == my_cert[tbs_cert_offset:tbs_cert_offset + tbs_cert_size]

# subprocess.run(("openssl", "asn1parse", "-inform", "DER", "-i", "-dump"), input=my_cert)

# Craft the GET DATA payload
payload = (
    b"\x53\x82" + struct.pack(">H", len(my_cert) + 9) +
    b"\x70\x82" + struct.pack(">H", len(my_cert)) +
    my_cert + b"\x71\x01\x00\xfe\x00"
)
decode_getdata_response(payload)

# Dump hexa
print("Dump:")
for i in range(0, len(payload), 16):
    print(f"    {payload[i:i + 16].hex()}")
