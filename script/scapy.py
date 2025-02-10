"""
For scapy setup and utilities
"""

from time import sleep

# https://scapy.readthedocs.io/en/stable/usage.html#sniffing
from scapy.all import AsyncSniffer, bind_layers, Packet, Ether
from scapy.fields import BitField
from mn_wifi.net import Mininet, info # type: ignore assumes import exists, it's from p4-utils

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


class Ipv4(Packet):
    fields_desc = [
        BitField("version", default=0, size=4),
        BitField("ihl", default=0, size=4),
        BitField("diffserv", default=0, size=8),
        BitField("total_len", default=0, size=16),
        BitField("identification", default=0, size=16),
        BitField("flags", default=0, size=3),
        BitField("frag_offset", default=0, size=13),
        BitField("ttl", default=0, size=8),
        BitField("protocol", default=0, size=8),
        BitField("checksum", default=0, size=16),
        BitField("src_addr", default=0, size=32),
        BitField("dst_addr", default=0, size=32),
    ]

bind_layers(Ether, Polka, type=POLKA_PROTO)
bind_layers(Polka, PolkaProbe, version=PROBE_VERSION)
bind_layers(PolkaProbe, Ipv4)




# TODO: Always send timestamp when edge detected
def start_sniffing(net: Mininet):
    info(f"*** 👃 Sniffing on {all_ifaces(net)}\n")

    sniffer = AsyncSniffer(
        # All ifaces
        iface=all_ifaces(net),
        # filter=f"ether proto {POLKA_PROTO:#x}",
        filter="ether proto 0x1234",
        store=True,
        # cb = lambda x: primeiro ou último
    )
    sniffer.start()
    # Waits for the minimum amount for the sniffer to be setup and run
    while not hasattr(sniffer, "stop_cb"):
        sleep(0.06)

    return sniffer
