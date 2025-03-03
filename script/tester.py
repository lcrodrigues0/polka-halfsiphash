"""
Network tests
"""

import json
import os.path as Path
from time import sleep
from typing import Iterable, TypeVar
import urllib.request as request

from mininet.log import info
from mn_wifi.bmv2 import (  # type: ignore assumes import exists, it's from p4-utils
    P4Switch,
)
from mn_wifi.net import (  # type: ignore
    Mininet,
)
from scapy.all import Packet, PacketList

from .scapy import Polka, PolkaProbe, start_sniffing
from .thrift import set_crc_parameters_common
from .topo import (
    CORE_THRIFT_CORE_OFFSET,
    LINK_SPEED,
    all_ifaces,
    connect_to_core_switch,
    linear_topology,
    polka_json_path,
    set_seed_e1,
    set_seed_e10,
)
from .calc_digests import calc_digests


T = TypeVar("T")


def check_digest(pkts: PacketList, seed_src: int, seed_dst: int):
    """
    Check if the packets have the expected digests
    """
    # for pkt in pkts:
    #     print(f"{pkt.getlayer(PolkaProbe).l_hash:#0{10}x}, {pkt.getlayer(PolkaProbe).timestamp:#0{10}x}")

    src_routeid = pkts[0].getlayer(Polka).route_id
    print(f"src_routeid: {src_routeid:#08x}")
    dst_routeid = pkts[len(pkts) // 2].getlayer(Polka).route_id
    print(f"dst_routeid (reply): {dst_routeid:#08x}")

    going = calc_digests(src_routeid, "s1", seed_src)
    reply = calc_digests(dst_routeid, "s10", seed_dst)

    def dup(it: Iterable[T]) -> Iterable[T]:
        """Every row is duplicated because the capture captures the packet twice, once for each monitored port"""
        for p in it:
            for _ in range(2):
                yield p

    going = list(dup(going))
    reply = list(dup(reply))

    routes: list[list[Packet]] = []
    marker_flag = False
    for pkt in pkts:
        polka_layer = pkt.getlayer(PolkaProbe)
        assert polka_layer is not None, "❌ PolkaProbe layer not found"
        if polka_layer.l_hash in (seed_src, seed_dst):
            marker_flag = not marker_flag
        if marker_flag:
            routes.append([pkt])
        else:
            routes[-1].append(pkt)
    assert len(routes) == 4, (
        f"❌ Expected 4 routes (send, reply, send back, reply back). Got {len(routes)}"
    )

    # Using Python3.8, so can't use `zip(*iterables, strict=True)`

    info("*** Checking collected packets\n")
    for route, expected_digests in zip(routes, (going, reply, reply, going)):
        info("*** 🔍 Tracing new route\n")
        for pkt, expected_digest in zip(route, expected_digests):
            polka = pkt.getlayer(Polka)
            assert polka is not None, "❌ Polka layer not found"
            probe = pkt.getlayer(PolkaProbe)
            assert probe is not None, "❌ Polka probe layer not found"
            l_hash = probe.l_hash
            info(
                f"*** Comparing {l_hash:#08x}, expects 0x{expected_digest.hex()} "
                f"on node {polka.ttl:#04x}:{pkt.sniffed_on} "
            )
            if l_hash == int.from_bytes(expected_digest, byteorder="big"):
                info("✅ ok\n")
            else:
                info("❌ Digest does not match\n")

        if len(route) != len(expected_digests):
            info(
                f"*** ❌ Route length does not match expected. Expected {len(expected_digests)}, got {len(route)}\n"
            )
            if len(route) < len(expected_digests):
                for digest in expected_digests[len(route) :]:
                    info(f"*** Missing digest 0x{digest.hex()}\n")
            else:
                info("*** ❌ Leftover packets:\n")
                for pkt in route[len(expected_digests) :]:
                    polka = pkt.getlayer(Polka)
                    assert polka is not None, "❌ Polka layer not found"
                    probe = pkt.getlayer(PolkaProbe)
                    assert probe is not None, "❌ Polka probe layer not found"
                    info(
                        f"*** {probe.l_hash:#08x} on node {polka.ttl:#04x}:{pkt.sniffed_on}\n"
                    )


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
    packet_loss_pct = net.ping(hosts=[first_host, last_host], timeout=3)
    # Comparing floats (bad), but it's fine because an exact 0.0% packet loss is expected
    assert packet_loss_pct == 0.0, f"Packet loss occurred: {packet_loss_pct}%"


def self():
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
        integrity(net)

        info("*** Breaking the polka routing on s3\n")

        # print(f"{net.ipBase=}")
        # print(f"{net.host=}")
        s3 = connect_to_core_switch(3)
        # Changes SwitchID from `0x0039` to `0x0000`
        set_crc_parameters_common(s3, "calc 0x0000 0x0 0x0 false false")

        try:
            integrity(net)
        except AssertionError:
            info("*** Test failed as expected\n")
        else:
            raise AssertionError("SelfTest error: Test should have failed")

        info("*** Restoring the polka routing on s3\n")
        set_crc_parameters_common(s3, "calc 0x0039 0x0 0x0 false false")

        integrity(net)
        net.stop()

        net = linear_topology(start=False)
        # sleep for a bit to let the network stabilize

        info("*** Testing the baseline signatures\n")

        net = set_seed_e1(net, 0x61E8D6E7)
        net = set_seed_e10(net, 0xDEADBEEF)

        net.start()
        net.staticArp()

        sleep(3)
        assert len(all_ifaces(net)) == 49, (
            f"❌ Expected 49 interfaces. Got {len(all_ifaces(net))}"
        )
        sniff = start_sniffing(net)
        info("Sniffer is setup.")
        integrity(net)
        info("*** Stopping sniffing\n")
        sleep(0.5)
        pkts = sniff.stop()
        assert pkts, "❌ No packets captured"
        pkts.sort(key=lambda pkt: pkt.time)

        check_digest(pkts, 0x61E8D6E7, 0xDEADBEEF)

        info("*** SELF TEST DONE ***\n")
    finally:
        net.stop()


def addition():
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
        assert len(links) == 1, (
            f"❌ Expected 1 link to be removed between {compromised.name} and {next_sw.name}"
        )

        info("*** Adding attacker\n")
        attacker = net.addSwitch(
            "s555",
            netcfg=True,
            json=Path.join(polka_json_path, "polka-attacker.json"),
            thriftport=CORE_THRIFT_CORE_OFFSET + 555,
            loglevel="debug",
            cls=P4Switch,
        )
        info("*** Linking attacker\n")
        # Taking the "default" port #3 which route from s4 -> s5 -> s6 should pass through on s5
        link = net.addLink(compromised, attacker, port1=3, port2=0, bw=LINK_SPEED)
        info(f"*** Created link {link}\n")
        link = net.addLink(attacker, next_sw, port1=1, port2=4, bw=LINK_SPEED)
        info(f"*** Created link {link}\n")
        # net.addLink(compromised, attacker, bw=LINK_SPEED)
        # net.addLink(attacker, next_sw, bw=LINK_SPEED)

        # The "next" is now port #4, which is mostly unused
        # The attacker will take the port #3 instead.
        # This is still used in traffic in the s6 -> s5 -> s4 direction
        new_link = net.addLink(compromised, next_sw, port1=4, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {new_link}\n")

        net = set_seed_e1(net, 0xABADCAFE)
        net = set_seed_e10(net, 0xBADDC0DE)

        net.start()
        net.staticArp()

        # sleep for a bit to let the network stabilize
        sleep(3)

        # CLI(net)

        # assert len(all_ifaces(net)) == 50, f"❌ Expected 50 interfaces. Got {len(all_ifaces(net))}"

        sniff = start_sniffing(net)

        integrity(net)

        info("*** Stopping sniffing\n")
        pkts = sniff.stop()
        assert pkts, "❌ No packets captured"
        pkts.sort(key=lambda pkt: pkt.time)

        check_digest(pkts, 0xABADCAFE, 0xBADDC0DE)

        info("*** ADDITION TEST DONE ***\n")

    finally:
        net.stop()


def detour():
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
        assert len(links) == 1, (
            f"❌ Expected 1 link to be removed between {prev_sw.name} and {skipped.name}"
        )
        links = net.delLinkBetween(next_sw, skipped, allLinks=True)
        assert len(links) == 1, (
            f"❌ Expected 1 link to be removed between {skipped.name} and {next_sw.name}"
        )

        info("*** Adding attacker\n")
        attacker = net.addSwitch(
            "s555",
            netcfg=True,
            json=Path.join(polka_json_path, "polka-attacker.json"),
            thriftport=CORE_THRIFT_CORE_OFFSET + 555,
            loglevel="debug",
            cls=P4Switch,
        )
        info("*** Linking attacker\n")
        # Taking the "default" port #3 which route from s4 -> s5 -> s6 should pass through on s5
        link = net.addLink(prev_sw, attacker, port1=3, port2=0, bw=LINK_SPEED)
        info(f"*** Created link {link}\n")
        link = net.addLink(attacker, next_sw, port1=1, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {link}\n")
        # relink skipped sw
        link = net.addLink(prev_sw, skipped, port1=4, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {link}\n")
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

        integrity(net)

        info("*** Stopping sniffing\n")
        pkts = sniff.stop()
        assert pkts, "❌ No packets captured"
        pkts.sort(key=lambda pkt: pkt.time)

        check_digest(pkts, 0xBADDC0DE, 0xDEADBEEF)

        info("*** DETOUR TEST DONE ***\n")

    finally:
        net.stop()


def outoforder():
    """
    Test if the network is protected against an outoforder attack.

    An outoforder attack is when the route is acessed using all defined router,
     and no other routers, but their order differ.
    """
    info("*** OUTOFORDER TEST ***\n")
    net = linear_topology(start=False)
    try:
        # Switch ports
        # Generally, on core POV:
        # eth0 = lo?
        # eth1 = edge
        # eth2 = previous
        # eth3 = next
        oor = net.switches[3:7]
        info("*** Replacing links with compromised route\n")

        for i in range(3):
            links = net.delLinkBetween(oor[i], oor[i + 1], allLinks=True)
            assert len(links) == 1, (
                f"❌ Expected 1 link to be removed between {oor[i].name} and {oor[i + 1].name}"
            )

        info("*** Linking back\n")
        # Taking the "default" port #3 which route from s4 -> s5 -> s6 should pass through on s5
        link = net.addLink(oor[0], oor[2], port1=3, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {link}\n")
        link = net.addLink(oor[2], oor[1], port1=3, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {link}\n")
        link = net.addLink(oor[1], oor[3], port1=3, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {link}\n")

        net = set_seed_e1(net, 0xABADCAFE)
        net = set_seed_e10(net, 0xBADDC0DE)

        net.start()
        net.staticArp()

        # sleep for a bit to let the network stabilize
        sleep(3)

        # CLI(net)

        # assert len(all_ifaces(net)) == 50, f"❌ Expected 50 interfaces. Got {len(all_ifaces(net))}"

        sniff = start_sniffing(net)

        integrity(net)

        info("*** Stopping sniffing\n")
        pkts = sniff.stop()
        assert pkts, "❌ No packets captured"
        pkts.sort(key=lambda pkt: pkt.time)

        check_digest(pkts, 0xABADCAFE, 0xBADDC0DE)

        info("*** OUT OF ORDER TEST DONE ***\n")

    finally:
        net.stop()


def subtraction():
    """
    Test if the network is protected against a subtraction attack.

    A subtraction attack is when a switch is skipped in the route,
    and the packets are sent directly to the next switch in the route.
    """


def skipping():
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
        assert len(links) == 1, (
            f"❌ Expected 1 link to be removed between {skipped.name} and {next_sw.name}"
        )
        links = net.delLinkBetween(skipped, prev_sw, allLinks=True)
        assert len(links) == 1, (
            f"❌ Expected 1 link to be removed between {skipped.name} and {prev_sw.name}"
        )

        new_link = net.addLink(prev_sw, next_sw, port1=3, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {new_link}\n")

        net = set_seed_e1(net, 0x61E8D6E7)
        net = set_seed_e10(net, 0xABADCAFE)

        net.start()
        net.staticArp()

        # sleep for a bit to let the network stabilize
        sleep(3)

        # CLI(net)

        # assert len(all_ifaces(net)) == 50, f"❌ Expected 50 interfaces. Got {len(all_ifaces(net))}"

        sniff = start_sniffing(net)

        integrity(net)

        info("*** Stopping sniffing\n")
        pkts = sniff.stop()
        assert pkts, "❌ No packets captured"
        pkts.sort(key=lambda pkt: pkt.time)

        check_digest(pkts, 0x61E8D6E7, 0xABADCAFE)

        info("*** SKIPPING TEST DONE ***\n")

    finally:
        net.stop()


def send_pkt(pkt):
    ENDPOINT_URL = "http://localhost:8283/"

    # Read headers
    polka_pkt = pkt.getlayer(Polka)
    assert polka_pkt is not None, "❌ Polka layer not found"

    probe_pkt = pkt.getlayer(PolkaProbe)

    req = request.Request(
        ENDPOINT_URL,
        data=json.dumps(
            {"route_id": polka_pkt.route_id, "probe": probe_pkt.to_dict()}
        ).encode("utf-8"),
    )
    res = request.urlopen(req)
    print(res.read().decode("utf-8"))


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

            send_pkt(pkt)
            return f"{pkt.sniffed_on} - {eth.src} -> {eth.dst} : => {probe.l_hash:#0{10}x}"

        sniff = start_sniffing(net, ifaces_fn=ifaces_fn, cb=sniff_cb)

        integrity(net)

        info("*** Stopping sniffing\n")
        sniff.stop()

        info("*** Hashes collected ***\n")

    finally:
        net.stop()

    info("*** ✅ Run finished.\n")
