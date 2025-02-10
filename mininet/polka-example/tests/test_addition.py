from os import path as Path
from mininet.log import info
from mn_wifi.bmv2 import P4Switch
from time import sleep

from utils.sniff import start_sniffing
from utils.check_digest import check_digest
from test_integrity import test_integrity
from linear_topology import linear_topology, CORE_THRIFT_CORE_OFFSET, LINK_SPEED, set_seed_e1, set_seed_e10


def test_addition():
    """
       Test if the network is protected against an addition attack

       An addition attack is when a new switch is added to the network between two existing switches,
       and the existing connections of surrounding switches = linear_topology()
    are not touched.
    """

    info("*** ADDITION TEST ***\n")
    net = linear_topology(start=False)
    try:
        # Switch ports
        # Generally, on core POV:
        # eth0 = lo?
        # eth1 = edge
        # eth2 = previous
        # eth3 = next
        compromised, next_sw = net.switches[4:6]
        info(f"*** Replacing {compromised.name}'s links with compromised route\n")

        links = net.delLinkBetween(compromised, next_sw, allLinks=True)
        assert (
            len(links) == 1
        ), f"❌ Expected 1 link to be removed between {compromised.name} and {next_sw.name}"

        info("*** Adding attacker\n")
        polka_json_dir = f"{Path.dirname(Path.abspath(__file__))}/polka/"
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
        link = net.addLink(compromised, attacker, port1=3, port2=0, bw=LINK_SPEED)
        info(f"*** Created link {link}")
        link = net.addLink(attacker, next_sw, port1=1, port2=4, bw=LINK_SPEED)
        info(f"*** Created link {link}")
        # net.addLink(compromised, attacker, bw=LINK_SPEED)
        # net.addLink(attacker, next_sw, bw=LINK_SPEED)

        # The "next" is now port #4, which is mostly unused
        # The attacker will take the port #3 instead.
        # This is still used in traffic in the s6 -> s5 -> s4 direction
        new_link = net.addLink(compromised, next_sw, port1=4, port2=2, bw=LINK_SPEED)
        info(f"### Created link {new_link}\n")

        net = set_seed_e1(net, 0xABADCAFE)
        net = set_seed_e10(net, 0xBADDC0DE)

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

        check_digest(pkts, 0xABADCAFE, 0xBADDC0DE)

        info("*** ADDITION TEST DONE ***\n")

    finally:
        net.stop()
