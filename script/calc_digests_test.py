from .calc_digests import calc_digests


def test_calc_digests_h1_h10():
    COLLECTED_HASHES = [
        b"\xab\xad\xca\xfe",
        b"\x55\x8f\x9e\xaf",
        b"\x7e\x64\x99\x16",
        b"\x68\x6d\x1f\x14",
        b"\x89\x16\xeb\xf4",
        b"\xa2\x1c\xd9\x6b",
        b"\x39\x3b\xb6\x7d",
        b"\xa0\xd7\x58\x4c",
        b"\x2c\x8f\x8e\x94",
        b"\xee\x4d\x7c\x51",
        b"\x49\x8f\x74\x6b",
    ]
    for hash in COLLECTED_HASHES:
        print(f"0x{hash.hex()}")
    assert (
        calc_digests(40134688781405407356790831164801586774996990884, "s1", 0xABADCAFE)
        == COLLECTED_HASHES
    )


def test_calc_digests_h10_h1():
    COLLECTED_HASHES = [
        b"\xba\xdd\xc0\xde",
        b"\xea\xe3\x9b\x01",
        b"\xb3\x2b\x4c\x06",
        b"\xed\x76\x30\xc0",
        b"\xee\x3e\x37\x9e",
        b"\xcd\x3f\x4b\x50",
        b"\xa9\x82\x7e\x52",
        b"\xbd\xff\x90\x9a",
        b"\xd8\xee\x14\xd9",
        b"\x47\xd7\x97\xb4",
        b"\xa9\xdb\x18\x69",
    ]
    for hash in COLLECTED_HASHES:
        print(f"0x{hash.hex()}")
    assert (
        calc_digests(259209858529954363229779036367232959135105947981, "s10", 0xBADDC0DE)
        == COLLECTED_HASHES
    )
