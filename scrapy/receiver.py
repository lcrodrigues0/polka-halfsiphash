#!/usr/bin/env python
import sys

from scapy.all import AsyncSniffer, bind_layers, Packet, Ether
from scapy.fields import BitField

from time import sleep


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


bind_layers(Ether, Polka, type=0x1234)
bind_layers(Polka, PolkaProbe, version=0xF1)
bind_layers(PolkaProbe, Ipv4)


def main():
    iface = sys.argv[1].split(",")

    print(f"Sniffing on {iface}")
    sys.stdout.flush()
    sniff = AsyncSniffer(iface=iface, filter="ether proto 0x1234", store=True)
    sniff.start()

    print("Hey")

    sleep(10)
    print("sniffing done")
    pkts = sniff.stop()

    for packet in pkts:
        print(packet.show())


if __name__ == "__main__":
    main()
