from os import path as Path
from os import getcwd
from mininet.log import info
from mn_wifi.bmv2 import P4Switch
from time import sleep

from linear_topology import linear_topology, CORE_THRIFT_CORE_OFFSET, LINK_SPEED, set_seed_e1, set_seed_e10
from utils.sniff import start_sniffing
from utils.check_digest import check_digest
from tests.test_integrity import test_integrity

def test_detour():
    """
    Test if the network is protected against a detour attack.

    A detour attack is when a new switch is added to the network between two existing switches,
    concurring with an existing switch, with the same connections as the existing switch.
    """
    info("*** DETOUR TEST ***\n")
    net = linear_topology(start=False)
    try:
        # Switch ports
        # Generally, on core POV:
        # eth0 = lo?
        # eth1 = edge
        # eth2 = previous
        # eth3 = next
        prev_sw, skipped, next_sw = net.switches[4:7]
        info(f"*** Replacing {prev_sw.name}'s links with compromised route\n")

        links = net.delLinkBetween(prev_sw, skipped, allLinks=True)
        assert (
            len(links) == 1
        ), f"❌ Expected 1 link to be removed between {prev_sw.name} and {skipped.name}"
        links = net.delLinkBetween(next_sw, skipped, allLinks=True)
        assert (
            len(links) == 1
        ), f"❌ Expected 1 link to be removed between {skipped.name} and {next_sw.name}"

        info("*** Adding attacker\n")
        
        # polka_json_dir = f"{Path.dirname(Path.abspath(__file__))}/polka/"
        polka_json_dir = f"{getcwd()}/polka/"

        attacker = net.addSwitch(
            "s555",
            netcfg=True,
            json=polka_json_dir + "polka-attacker.json",
            thriftport=CORE_THRIFT_CORE_OFFSET + 555,
            loglevel="debug",
            cls=P4Switch,
        )
        info("*** Linking attacker\n")
        # Taking the "default" port #3 which route from s4 -> s5 -> s6 should pass through on s5
        link = net.addLink(prev_sw, attacker, port1=3, port2=0, bw=LINK_SPEED)
        info(f"*** Created link {link}")
        link = net.addLink(attacker, next_sw, port1=1, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {link}")
        # relink skipped sw
        link = net.addLink(prev_sw, skipped, port1=4, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {link}")
        link = net.addLink(skipped, next_sw, port1=3, port2=4, bw=LINK_SPEED)

        net = set_seed_e1(net, 0xBADDC0DE)
        net = set_seed_e10(net, 0xDEADBEEF)

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

        check_digest(pkts, 0xBADDC0DE, 0xDEADBEEF)

        info("*** DETOUR TEST DONE ***\n")

    finally:
        net.stop()

