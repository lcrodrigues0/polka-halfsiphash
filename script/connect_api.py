from mn_wifi.net import info, Mininet
from time import sleep
from scapy.all import Packet

from script.tester import linear_topology, Polka, PolkaProbe, integrity, start_sniffing
from script.call_api import call_deploy_flow_contract, call_set_ref_sig, hash_flow_id, call_log_probe

    

def integrity(net: Mininet):
    """
    Test the integrity of the network, this is to be used in a suite of tests
    """

    first_host = net.get("h1")
    assert first_host is not None, "Host h1 not found"
    last_host = net.get(
        "h10"
    )  # h11 is right beside h1, so wouldn't traverse all switches
    assert last_host is not None, "Host h10 not found"

    info(
        "\n*** Testing network integrity\n"
        f"    a ping from {first_host.name} to {last_host.name},\n"
        "    goes through all core switches.\n"
    )
    
    first_host.cmd('ping -c 1', last_host.IP())


def collect_hashes():
    """
    Collect the hashes (all intermediary) from the network
    """

    info("*** Starting run for collecting hash and intermediaries\n")

    net = linear_topology(start=False)
    try:
        net.start()
        net.staticArp()

        # sleep for a bit to let the network stabilize
        sleep(3)

        flow_id = hash_flow_id("10.0.1.1", "0", "10.0.10.10", "0")
        call_deploy_flow_contract(flow_id)

        def ifaces_fn(net: Mininet):
            import re
            iname = re.compile(r"e\d+-eth2")
            
            return [
                iface
                for switch in net.switches
                for iface in switch.intfNames()
                if iname.match(iface)
            ]

        def sniff_cb(pkt: Packet):
            assert pkt.sniffed_on is not None, (
                "❌ Packet not sniffed on any interface. WTF."
            )
            polka = pkt.getlayer(Polka)
            assert polka is not None, "❌ Polka layer not found"
            probe = pkt.getlayer(PolkaProbe)
            assert probe is not None, "❌ PolkaProbe layer not found"
            eth = pkt.getlayer("Ether")
            assert eth is not None, "❌ Ether layer not found"

            if(probe.timestamp == probe.l_hash):
                call_set_ref_sig(pkt)
            else:
                call_log_probe(pkt)

            return f"{pkt.sniffed_on} - {eth.src} -> {eth.dst} : => {probe.l_hash:#0{10}x}"

        sniff = start_sniffing(net, ifaces_fn=ifaces_fn, cb=sniff_cb)

        integrity(net)

        info("*** Stopping sniffing\n")
        sleep(2)
        sniff.stop()

        info("*** Hashes collected ***\n")

    finally:
        net.stop()

    info("*** ✅ Run finished.\n")
