"""
For scapy setup and utilities
"""

from typing import Callable, Optional

from time import sleep

# https://scapy.readthedocs.io/en/stable/usage.html#sniffing
from scapy.all import AsyncSniffer, bind_layers, Packet, BitField
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, UDP, ICMP, IP
from mn_wifi.net import Mininet, info  # type: ignore assumes import exists, it's from p4-utils

from .topo import all_ifaces

POLKA_PROTO = 0x1234
PROBE_VERSION = 0xF1


# order matters. It is the order in the packet header
class Polka(Packet):
    fields_desc = [
        BitField("version", default=0, size=8),
        BitField("ttl", default=0, size=8),
        BitField("proto", default=0, size=16),
        BitField("route_id", default=0, size=160),
    ]


class PolkaProbe(Packet):
    fields_desc = [
        BitField("timestamp", default=0, size=32),
        BitField("l_hash", default=0, size=32),
    ]

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "l_hash": self.l_hash,
        }


bind_layers(Ether, Polka, type=POLKA_PROTO)
bind_layers(Polka, PolkaProbe, version=PROBE_VERSION)
bind_layers(PolkaProbe, IP)


def start_sniffing(net: Mininet, ifaces_fn = all_ifaces, cb: Optional[Callable[[Packet], Optional[str]]] = None):
    info(f"*** 👃 Sniffing on {ifaces_fn(net)}\n")

    sniffer = AsyncSniffer(
        # All ifaces
        iface=ifaces_fn(net),
        # filter=f"ether proto {POLKA_PROTO:#x}",
        filter="ether proto 0x1234",
        store=True,
        prn=cb,
    )
    sniffer.start()
    # Waits for the minimum amount for the sniffer to be setup and run
    while not hasattr(sniffer, "stop_cb"):
        sleep(0.06)

    return sniffer
