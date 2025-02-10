from mininet.log import info
from time import sleep

from linear_topology import linear_topology, LINK_SPEED, set_seed_e1, set_seed_e10
from utils.sniff import start_sniffing
from utils.check_digest import check_digest
from test_integrity import test_integrity

def test_skipping():
    """
    Test if the network is protected against a skipping attack.

    A skipping attack is when a route skips the core entirely and goes directly to the edge.
    """

    info("*** SKIPPING TEST ***\n")
    net = linear_topology(start=False)
    try:
        # Switch ports
        # Generally, on core POV:
        # eth0 = lo?
        # eth1 = edge
        # eth2 = previous
        # eth3 = next
        prev_sw, skipped, next_sw = net.switches[3:6]
        info(f"*** Replacing {skipped.name}'s links with compromised route\n")

        links = net.delLinkBetween(skipped, next_sw, allLinks=True)
        assert (
            len(links) == 1
        ), f"❌ Expected 1 link to be removed between {skipped.name} and {next_sw.name}"
        links = net.delLinkBetween(skipped, prev_sw, allLinks=True)
        assert (
            len(links) == 1
        ), f"❌ Expected 1 link to be removed between {skipped.name} and {prev_sw.name}"

        new_link = net.addLink(prev_sw, next_sw, port1=3, port2=2, bw=LINK_SPEED)
        info(f"### Created link {new_link}\n")

        net = set_seed_e1(net, 0x61E8D6E7)
        net = set_seed_e10(net, 0xABADCAFE)

        net.start()
        net.staticArp()

        # sleep for a bit to let the network stabilize
        sleep(3)

        # CLI(net)

        # assert len(all_ifaces(net)) == 50, f"❌ Expected 50 interfaces. Got {len(all_ifaces(net))}"

        sniff = start_sniffing(net)

        test_integrity(net)

        info("*** Stopping sniffing\n")
        pkts = sniff.stop()
        pkts.sort(key=lambda pkt: pkt.time)

        check_digest(pkts, 0x61E8D6E7, 0xABADCAFE)

        info("*** SKIPPING TEST DONE ***\n")

    finally:
        net.stop()

