# from typing import Annotated

# _64Bit = Annotated[bytes, "64-bit"]
# _32Bit = Annotated[bytes, "32-bit"]


class State:
    def __init__(self, key: bytes) -> None:
    # def __init__(self, key: _64Bit) -> None:
        k0 = int.from_bytes(key[:4], byteorder="big")
        k1 = int.from_bytes(key[4:], byteorder="big")
        self.v0 = k0 ^ 0x0000_0000
        self.v1 = k1 ^ 0x0000_0000
        self.v2 = k0 ^ 0x6C79_6765
        self.v3 = k1 ^ 0x7465_6462

    def rotl(self, x: int, b: int) -> int:
        # Needs to bit-mask for intentional overflow behavior
        return ((x << b) | (x >> (32 - b))) & 0xFFFF_FFFF

    def sipround(self) -> None:
        """Performs a single round of the SipHash shuffle algorithm."""
        # Needs to bit-mask for intentional overflow behavior
        self.v0 = (self.v0 + self.v1) & 0xFFFF_FFFF
        self.v1 = self.rotl(self.v1, 5)
        self.v1 = self.v1 ^ self.v0
        self.v0 = self.rotl(self.v0, 16)
        self.v2 = (self.v2 + self.v3) & 0xFFFF_FFFF
        self.v3 = self.rotl(self.v3, 8)
        self.v3 = self.v3 ^ self.v2
        self.v0 = (self.v0 + self.v3) & 0xFFFF_FFFF
        self.v3 = self.rotl(self.v3, 7)
        self.v3 = self.v3 ^ self.v0
        self.v2 = (self.v2 + self.v1) & 0xFFFF_FFFF
        self.v1 = self.rotl(self.v1, 13)
        self.v1 = self.v1 ^ self.v2
        self.v2 = self.rotl(self.v2, 16)
        # print(
        #     self.v0.bit_length(),
        #     self.v1.bit_length(),
        #     self.v2.bit_length(),
        #     self.v3.bit_length(),
        # )


def siphash(key: bytes, data: bytes) -> bytes:
# def siphash(key: _64Bit, data: _32Bit) -> _32Bit:
    """Hashes a single datum using especified key. Does not keep state. (so it is single-use|stateless)"""
    s = State(key)
    b = 0x0400_0000
    m = int.from_bytes(data, byteorder="little")

    s.v3 ^= m
    s.sipround()
    s.sipround()
    s.v0 ^= m

    s.v3 ^= b
    s.sipround()
    s.sipround()
    s.v0 ^= b
    s.v2 ^= 0x0000_00FF

    s.sipround()
    s.sipround()
    s.sipround()
    s.sipround()
    
    r = (s.v1 ^ s.v3).to_bytes(4, byteorder="little")

    # print(f"r: 0x{r.hex()}")

    return r
