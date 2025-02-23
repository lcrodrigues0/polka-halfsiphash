from .siphash import siphash


KEY = 0x0302_0100_0706_0504
LHASH = 0xABAD_CAFE
EXPECTED = 0xCEFC_57C9


def test_siphash():
    assert siphash(
        KEY.to_bytes(8, byteorder="big"), LHASH.to_bytes(4, byteorder="big")
    ) == EXPECTED.to_bytes(4, byteorder="big")
