from mininet.log import info
from mn_wifi.bmv2 import P4Switch
from time import sleep

from linear_topology import linear_topology, set_seed_e1, set_seed_e10, connect_to_core_switch, set_crc_parameters_common, all_ifaces
from utils.sniff import start_sniffing
from utils.check_digest import check_digest
from test_integrity import test_integrity

def test_self():
    """
    The self-test's purpose is to test if we can run the network
    and if the network is working as expected.
    It also tests if our tooling is working as expected.
    """
    net = linear_topology()
    try:
        # sleep for a bit to let the network stabilize
        sleep(3)

        info("*** SELF TEST ***\n")
        test_integrity(net)

        info("*** Breaking the polka routing on s3\n")

        # print(f"{net.ipBase=}")
        # print(f"{net.host=}")
        s3 = connect_to_core_switch(3)
        # Changes SwitchID from `0x0039` to `0x0000`
        set_crc_parameters_common(s3, "calc 0x0000 0x0 0x0 false false")

        try:
            test_integrity(net)
        except AssertionError:
            info("*** Test failed as expected\n")
        else:
            raise AssertionError("SelfTest error: Test should have failed")

        info("*** Restoring the polka routing on s3\n")
        set_crc_parameters_common(s3, "calc 0x0039 0x0 0x0 false false")

        test_integrity(net)
        net.stop()

        net = linear_topology(start=False)
        # sleep for a bit to let the network stabilize

        info("*** Testing the baseline signatures\n")

        net = set_seed_e1(net, 0x61E8D6E7)
        net = set_seed_e10(net, 0xDEADBEEF)

        net.start()
        net.staticArp()

        sleep(3)
        assert (
            len(all_ifaces(net)) == 49
        ), f"❌ Expected 49 interfaces. Got {len(all_ifaces(net))}"
        sniff = start_sniffing(net)
        info("Sniffer is setup.")
        test_integrity(net)
        info("*** Stopping sniffing\n")
        sleep(0.5)
        pkts = sniff.stop()
        pkts.sort(key=lambda pkt: pkt.time)

        check_digest(pkts, 0x61E8D6E7, 0xDEADBEEF)

        info("*** SELF TEST DONE ***\n")
    finally:
        net.stop()
