from mininet.log import info
from mn_wifi.net import Mininet_wifi
from scapy.all import AsyncSniffer
from time import sleep

from linear_topology import all_ifaces

def start_sniffing(net: Mininet_wifi):
    info(f"*** 👃 Sniffing on {all_ifaces(net)}\n\n")

    sniffer = AsyncSniffer(
        # All ifaces
        iface=all_ifaces(net),
        # filter=f"ether proto {POLKA_PROTO:#x}",
        filter="ether proto 0x1234",
        store=True,
    )
    sniffer.start()
    # Waits for the minimum amount for the sniffer to be setup and run
    while not hasattr(sniffer, "stop_cb"):
        sleep(0.06)

    return sniffer