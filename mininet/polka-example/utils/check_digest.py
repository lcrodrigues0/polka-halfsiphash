from typing import Iterable, TypeVar
from scapy.all import Packet
from mininet.log import info

from linear_topology import Polka, PolkaProbe

# H1 -> H10
BASE_DIGESTS = {
    # On the way to h10
    "h1-h10": {
        # Seed, on ingress edge
        0x61E8D6E7: [
            0x61E8D6E7,
            0xAE91434C,
            0x08C97F5F,
            0xEFF1AAD2,
            0x08040C89,
            0xAA99AE2E,
            0x7669685E,
            0x03E1E388,
            0x2138FFD3,
            0x1EF2CBBE,
            0x99C5FE05,
        ],
        0xDEADBEEF: [
            0xDEADBEEF,
            0x3E2E3B36,
            0x2CBD4C0A,
            0x7C33927C,
            0x132B32F9,
            0x0F50152C,
            0x7B9D3AF9,
            0x8379E9C4,
            0xBAE44591,
            0x76D807C1,
            0xF5781630,
        ],
        0xBADDC0DE: [
            0xBADDC0DE,
            0x3EF96770,
            0x2DCA9942,
            0x11797334,
            0x98081E3E,
            0x3332E012,
            0x22996AFD,
            0x8FA3987D,
            0xF4B50950,
            0xD0C29E67,
            0x13FF41C1,
        ],
        0xABADCAFE: [
            0xABADCAFE,
            0x432CF798,
            0xE04DF688,
            0xE8F0142C,
            0xB452022A,
            0x4450D2D2,
            0xE9367B57,
            0x991182C1,
            0x35E72E11,
            0xAA152EB9,
            0x1A1573E7,
        ],
    },
    # Reply, on the way back
    "h10-h1": {
        # Seed, ON INGRESS EDGE
        0x61E8D6E7: [
            0x61E8D6E7,
            0xCFFABC9F,
            0x69409E70,
            0xF3E992E0,
            0x8DDE192B,
            0x92B098FA,
            0x1115A62C,
            0x41E1B5E0,
            0x227F0B72,
            0x82FC6346,
            0xD01E3E0F,
        ],
        0xDEADBEEF: [
            0xDEADBEEF,
            0x5F45C4E5,
            0x4D34AD25,
            0x602BAA4E,
            0x96F1275B,
            0x377923F8,
            0x1CE1F48B,
            0xC179BFAC,
            0xB9A3B130,
            0xEAD6AF39,
            0xBCA3D63A,
        ],
        0xBADDC0DE: [
            0xBADDC0DE,
            0x5F9298A3,
            0x4C43786D,
            0X0D614B06,
            0x1DD20B9C,
            0x0B1BD6C6,
            0x45E5A48F,
            0xCDA3CE15,
            0xF7F2FDF1,
            0x4CCC369F,
            0x5A2481CB,
        ],
        0xABADCAFE: [
            0xABADCAFE,
            0x2247084B,
            0x81C417A7,
            0xF4E82C1E,
            0x31881788,
            0x7C79E406,
            0x8E4AB525,
            0xDB11D4A9,
            0x36A0DAB0,
            0x361B8641,
            0x53CEB3ED,
        ],
    },
}

T = TypeVar("T")

def check_digest(pkts: Iterable[Packet], seed_src: int, seed_dst: int):
    """
    Check if the packets have the expected digests
    """
    # for pkt in pkts:
    #     print(f"{pkt.getlayer(PolkaProbe).l_hash:#0{10}x}, {pkt.getlayer(PolkaProbe).timestamp:#0{10}x}")

    going = BASE_DIGESTS["h1-h10"][seed_src]
    reply = BASE_DIGESTS["h10-h1"][seed_dst]

    def dup(it: Iterable[T]) -> Iterable[T]:
        """Every row is duplicated because the capture captures the packet twice, once for each monitored port"""
        for p in it:
            for _ in range(2):
                yield p

    going = list(dup(going))
    reply = list(dup(reply))

    routes: list[list[Packet]] = []
    marker_flag = False
    for pkt in pkts:
        if pkt.getlayer(PolkaProbe).l_hash in (seed_src, seed_dst):
            marker_flag = not marker_flag
        if marker_flag:
            routes.append([pkt])
        else:
            routes[-1].append(pkt)
    assert (
        len(routes) == 4
    ), f"❌ Expected 4 routes (send, reply, send back, reply back). Got {len(routes)}"

    # Using Python3.8, so can't use `zip(*iterables, strict=True)`

    info("*** Checking collected packets\n")
    for route, expected_digests in zip(routes, (going, reply, reply, going)):
        info("*** 🔍 Tracing new route\n")
        for pkt, expected_digest in zip(route, expected_digests):
            polka = pkt.getlayer(Polka)
            probe = pkt.getlayer(PolkaProbe)
            l_hash = probe.l_hash
            info(
                f"*** Comparing {l_hash:#0{10}x}, expects {expected_digest:#0{10}x} "
                f"on node {polka.ttl:#0{6}x}:{pkt.sniffed_on} "
            )
            if l_hash == expected_digest:
                info("✅ ok\n")
            else:
                info("❌ Digest does not match\n")

        if len(route) != len(expected_digests):
            info(
                f"*** ❌ Route length does not match expected. Expected {len(expected_digests)}, got {len(route)}\n"
            )
            if len(route) < len(expected_digests):
                for digest in expected_digests[len(route) :]:
                    info(f"*** Missing digest {digest:#0{10}x}\n")
            else:
                info("*** ❌ Leftover packets:\n")
                for pkt in route[len(expected_digests) :]:
                    polka = pkt.getlayer(Polka)
                    probe = pkt.getlayer(PolkaProbe)
                    info(
                        f"*** {probe.l_hash:#0{10}x} on node {polka.ttl:#0{6}x}:{pkt.sniffed_on}\n"
                    )
