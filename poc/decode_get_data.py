#!/usr/bin/env python3
"""Decode the response of a get_data command received by the host

https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#get-data
"""
from typing import Any, Optional
import subprocess

responses_from_pcap = (
    # Class 00, Instruction 0xcb, P1 0x3f, P2 0xff, Data  5c 03 5f c1 0d => "TAG", 3 bytes, 5f c1 0d = RETIRED1 certificate
    bytes.fromhex("""
        538201bf708201b6308201b230820158
        a00302010202141dd8781b14f8b445d4
        deddf5dd4afe40ce7e3c5e300a06082a
        8648ce3d040302304d311b3019060355
        040a0c126167652d706c7567696e2d79
        7562696b6579310e300c060355040b0c
        05302e332e30311e301c06035504030c
        15616765206964656e74697479203265
        3037663234623020170d323230373034
        3133313231315a180f39393939313233
        313233353935395a304d311b30190603
        55040a0c126167652d706c7567696e2d
        797562696b6579310e300c060355040b
        0c05302e332e30311e301c0603550403
        0c15616765206964656e746974792032
        653037663234623059301306072a8648

        ce3d020106082a8648ce3d0301070342
        00041c2909e250343e78d472d41ecc08
        d5b6ec36fe427db97f264adcbdc5f827
        6968da1ede79f9bc5e53a00360ad2ee6
        c7fcb48250cb640350231e1dd39151d4
        76f4a31430123010060a2b0601040182
        c40a030804020202300a06082a8648ce
        3d040302034800304502202d1ae8c546
        6ceca1e21e8b9d3c8166c0c5a8084ccf
        af00563b7da1fb158ae813022100a89a
        128b2fcd3e849e7e175ea097be100295
        5a48ed033344a37fba32ca5dde9c7101
        00fe00"""
    ),
    # Data from "no pin"
    bytes.fromhex("""
        538201bf708201b6308201b230820159
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
        8958658f0b3b2ed9744894a9b32f7101
        00fe00"""
    ),
)


class ParsedBuffer:
    """A buffer being parsed, for example to unmarshal data"""
    def __init__(self, buffer: bytes, name: Optional[str] = None, ensure_end_on_exit: bool = True) -> None:
        self.buffer = buffer
        self.pos = 0
        self.name = name
        self.ensure_end_on_exit = ensure_end_on_exit

    def remaining_size(self) -> int:
        return len(self.buffer) - self.pos

    def remaining(self) -> bytes:
        return self.buffer[self.pos:]

    def read_remaining(self) -> bytes:
        value = self.buffer[self.pos:]
        self.pos = len(self.buffer)
        return value

    def assert_end(self) -> None:
        if self.pos != len(self.buffer):
            if self.name:
                raise RuntimeError(f"while parsing {self.name}, remaining {self.remaining_size()} bytes: {self.remaining().hex()}")  # noqa
            raise RuntimeError(f"remaining {self.remaining_size()} bytes: {self.remaining().hex()}")

    def __enter__(self) -> 'ParsedBuffer':
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self.ensure_end_on_exit:
            self.assert_end()

    def read_bytes(self, size: int) -> bytes:
        assert size >= 0
        assert self.pos + size <= len(self.buffer)
        value = self.buffer[self.pos:self.pos + size]
        self.pos += size
        return value

    def read_bool(self) -> bool:
        value = self.read_bytes(1)
        if value == b"\x00":
            return False
        if value == b"\x01":
            return True
        raise ValueError(f"Unexpected serialized boolean {value!r}")

    def read_u8(self) -> int:
        return int.from_bytes(self.read_bytes(1), "big")

    def read_u16(self) -> int:
        return int.from_bytes(self.read_bytes(2), "big")

    def read_u32(self) -> int:
        return int.from_bytes(self.read_bytes(4), "big")

    def read_asn1_length(self) -> int:
        size_marker = self.read_u8()
        if size_marker < 0x80:
            return size_marker
        if size_marker == 0x82:
            return self.read_u16()
        raise NotImplementedError(f"Size marker {size_marker:#04x}")


def decode_getdata_response(data):
    with ParsedBuffer(data) as buf:
        assert buf.read_u8() == 0x53
        size = buf.read_asn1_length()
        assert size == buf.remaining_size()
        assert buf.read_u8() == 0x70
        size = buf.read_asn1_length()

        # ASN.1 certificate
        assert size == buf.remaining_size() - 5
        certificate = buf.read_bytes(size)
        
        # 71 01 00 (compression) FE 00 (LRC)
        assert buf.remaining_size() == 5
        assert buf.read_u8() == 0x71
        assert buf.read_u8() == 0x01
        assert buf.read_u8() == 0x00
        assert buf.read_u8() == 0xfe
        assert buf.read_u8() == 0x00

    # X.509 certificate, https://datatracker.ietf.org/doc/html/rfc2459
    with ParsedBuffer(certificate) as buf:
        assert buf.read_u8() == 0x30
        size = buf.read_asn1_length()
        assert size == buf.remaining_size()

        assert buf.read_u8() == 0x30
        size = buf.read_asn1_length()
        tbscert = buf.read_bytes(size)
        assert buf.read_u8() == 0x30
        size = buf.read_asn1_length()
        signalg = buf.read_bytes(size)
        assert buf.read_u8() == 0x03
        size = buf.read_asn1_length()
        signature = buf.read_bytes(size)

        print(f"tbsCertificate = {tbscert.hex()}")
        print(f"signatureAlgorithm = {signalg.hex()}")
        print(f"signatureValue = {signature.hex()}")

        assert signalg == bytes.fromhex("06082a8648ce3d040302")  # ecdsa-with-SHA256

    subprocess.run(("openssl", "asn1parse", "-inform", "DER", "-i", "-dump"), input=certificate)
    subprocess.run(("openssl", "x509", "-inform", "DER", "-noout", "-text"), input=certificate)


# print(get_data_response.hex())
# Format: https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html#encoded-certificate
# 53 L1 70 L2 --X.509 certificate--
if __name__ == "__main__":
    for data in responses_from_pcap:
        decode_getdata_response(data)
