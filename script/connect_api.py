from mn_wifi.net import info, Mininet
from time import sleep
from scapy.all import Packet

from script.tester import linear_topology, Polka, PolkaProbe, integrity, start_sniffing
from script.call_api import call_deploy_flow_contract, call_set_ref_sig, hash_flow_id, call_log_probe
from .siphash import siphash
from .polka_nhop import NODES, Node

edge_nodes = [f"e{i}" for i in range(1, 11)]

def calc_digests(route_id: int, node_id: str, seed: int) -> list:
    """Calculates the digest for each node in the path.
    Returns a list of digests.

    @param node The name or index of the node to start from. If hostname is `s1`, index should be `1`.
    """
    if node_id in edge_nodes:
        print(node_id)
        node_id = f"s{node_id[1:]}"
        print(node_id)

    if isinstance(node_id, str):
        node = [n for n in NODES if n.name == node_id][0]
    else:
        raise ValueError("Invalid `node_id` parameter")

    digests = [seed.to_bytes(4, byteorder="big")]
    visited_nodes = []
    while True:
        if node in visited_nodes:
            raise ValueError(f"Loop detected. Visited {visited_nodes!r}")
        visited_nodes.append(node)

        exit_port = node.nhop(route_id)
        keystr = f"{node.node_id:016b}{exit_port:09b}{seed:032b}{0:07b}"
        key = int(keystr, base=2).to_bytes(8, byteorder="big")
        # print(f"key: 0x{key.hex()}")

        new_digest = siphash(key, digests[-1])
        digests.append(new_digest)
        # print(f"{node.name} => 0x{digests[-1].hex()}")

        if exit_port < 2:
            # This means the packet has reached the edge
            # print(f"EXIT PORT {exit_port} on {node.name}")
            break
        next_node = node.ports[exit_port]
        assert isinstance(next_node, Node), f"Invalid next node: {next_node}"
        node: Node = next_node

    return digests

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

def connect_api():
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

            print(f"{pkt.time} : {pkt.sniffed_on} - {eth.src} -> {eth.dst} => {probe.l_hash:#0{10}x}")
        sniff = start_sniffing(net, ifaces_fn=ifaces_fn, cb=sniff_cb)

        integrity(net)

        info("*** Stopping sniffing\n")
        sleep(2)            # Time to finish printing the logs

        sniff.stop()

        info("*** Hashes collected ***\n")

    finally:
        net.stop()

    info("*** ✅ Run finished.\n")

def get_hashes_hops():
    """
        Return hash at each hop
    """

    info("*** Starting run for collecting hash and intermediaries\n")

    net = linear_topology(start=False)
    try:
        net.start()
        net.staticArp()

        # sleep for a bit to let the network stabilize
        sleep(3)

        def ifaces_fn(net: Mininet):
            import re
            iname = re.compile(r"\S\d+-eth2")
            
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


            if probe.timestamp == probe.l_hash:
                import re 
                pattern = r"\S\d+"
                match = re.search(pattern, pkt.sniffed_on)
                
                if match:
                    print(f"Reference Signature: 0x{calc_digests(polka.route_id, match.group(), probe.timestamp)[-1].hex()}")
                
            print(f"{pkt.sniffed_on} - {eth.src} -> {eth.dst} : => {probe.l_hash:#0{10}x}")

        sniff = start_sniffing(net, ifaces_fn=ifaces_fn, cb=sniff_cb)

        integrity(net)

        info("*** Stopping sniffing\n")
        sleep(2)
        sniff.stop()

        info("*** Hashes collected ***\n")

    finally:
        net.stop()

    info("*** ✅ Run finished.\n")
