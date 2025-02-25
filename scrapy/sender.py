#!/usr/bin/env python
from scapy.all import sendp, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, Raw
from scapy.fields import BitField
import time


class SourceRoute(Packet):
    fields_desc = [
        BitField("routeid", 0, 160),
        BitField("pot_k", 0, 32),
    ]


bind_layers(Ether, SourceRoute, type=0x1234)


def main():
    iface = "s1-eth1"

    print(f"Sending on interface {iface} to 10.0.2.2")

    while True:
        # routeid = 238533108820371
        # routeid = 82148760745903
        routeid = 238533108821907
        pkt = Ether(src="00:00:00:00:01:01", dst="00:00:00:00:02:02")
        try:
            pkt = pkt / SourceRoute(routeid=routeid, pot_k=3980420111)
            # pkt = pkt / SourceRoute(routeid=routeid)
        except ValueError:
            print("Exception raised")
            pass

        pkt = (
            pkt
            / IP(src="10.0.1.1", dst="10.0.2.2")
            / UDP(dport=4321, sport=1234)
            / Raw("X" * 10)
        )
        pkt.show()
        sendp(pkt, iface=iface)
        time.sleep(2)

        # sendp(pkt, iface=iface, count=2, inter=1.0 / 2900)


if __name__ == "__main__":
    main()
