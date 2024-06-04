#!/usr/bin/python
# Copyright [2019-2022] Universidade Federal do Espirito Santo
#                       Instituto Federal do Espirito Santo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from os import path as Path
from typing import Iterable, Callable
from time import sleep

from mininet.log import setLogLevel, info, debug
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.bmv2 import P4Switch


from polka_controller.controller_polka import (
    thrift_connect_standard,
    set_crc_parameters_common,
)

from scapy.all import AsyncSniffer, bind_layers, Packet, Ether
from scapy.fields import BitField


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


# from mininet.term import makeTerm
# from mininet.node import RemoteController

N_SWITCHES = 10
BW = 10

CORE_THRIFT_CORE_OFFSET = 50000
EDGE_THRIFT_CORE_OFFSET = 50100

POLKA_PROTO = 0x1234
PROBE_VERSION = 0xF1

bind_layers(Ether, Polka, type=POLKA_PROTO)
bind_layers(Polka, PolkaProbe, version=PROBE_VERSION)
bind_layers(PolkaProbe, Ipv4)


def linear_topology_add_hosts(net):
    hosts = []
    info("*** Adding hosts\n")
    for i in range(1, N_SWITCHES + 1):
        ip = f"10.0.{i}.{i}"
        mac = f"00:00:00:00:{i:02x}:{i:02x}"
        host = net.addHost(f"h{i}", ip=ip, mac=mac)
        hosts.append(host)

    # host 11
    i_1, i_2 = 1, N_SWITCHES + 1
    ip = f"10.0.{i_1}.{i_2}"
    mac = f"00:00:00:00:{i_1:02x}:{i_2:02x}"
    host = net.addHost(f"h{N_SWITCHES + 1}", ip=ip, mac=mac)
    hosts.append(host)

    return (net, hosts)


def linear_topology_add_switches(net):

    edges = []
    cores = []

    info("*** Adding P4Switches (core)\n")
    for i in range(1, N_SWITCHES + 1):
        # read the network configuration
        path = Path.dirname(Path.abspath(__file__))
        # Add P4 switches (core)
        switch = net.addSwitch(
            f"s{i}",
            netcfg=True,
            json=f"{path}/polka/polka-core.json",
            thriftport=CORE_THRIFT_CORE_OFFSET + int(i),
            switch_config=f"{path}/polka/config/s{i}-commands.txt",
            loglevel="debug",
            cls=P4Switch,
        )
        cores.append(switch)

    info("*** Adding P4Switches (edge)\n")
    for i in range(1, N_SWITCHES + 1):
        # read the network configuration
        path = Path.dirname(Path.abspath(__file__))
        # add P4 switches (edge)
        switch = net.addSwitch(
            f"e{i}",
            netcfg=True,
            json=f"{path}/polka/polka-edge.json",
            thriftport=EDGE_THRIFT_CORE_OFFSET + int(i),
            switch_config=f"{path}/polka/config/e{i}-commands.txt",
            loglevel="debug",
            cls=P4Switch,
        )
        edges.append(switch)

    return (net, cores, edges)


def linear_topology() -> Mininet_wifi:
    "Create a network."
    net = Mininet_wifi()

    # linkopts = dict()
    net, hosts = linear_topology_add_hosts(net)
    net, cores, edges = linear_topology_add_switches(net)

    info("*** Creating links\n")
    for i in range(0, N_SWITCHES):
        net.addLink(hosts[i], edges[i], bw=BW)
        net.addLink(edges[i], cores[i], bw=BW)

    last_switch = None

    for i in range(0, N_SWITCHES):
        switch = cores[i]

        if last_switch:
            net.addLink(last_switch, switch, bw=BW)
        last_switch = switch

    # host 11
    net.addLink(hosts[-1], edges[0], bw=BW)

    info("*** Starting network\n")
    net.start()
    net.staticArp()

    # disabling offload for rx and tx on each host interface
    for host in hosts:
        host.cmd(f"ethtool --offload {host.name}-eth0 rx off tx off")

    return net


def gen_show_function(sw: str) -> Callable[[Packet], None]:
    """
    Generate a function that will show the packet if it is destined to the switch
    """

    def show(packet: Packet):
        """
        Show the packet if it is destined to the switch
        """
        print(f"Packet received by {sw}")
        packet.show()

    return show


def test_integrity(net):
    """
    Test the integrity of the network, this is to be used in a suite of tests
    """
    first_host = net.hosts[0]
    last_host = net.hosts[-2]
    info(
        "*** Testing network integrity\n"
        f"    a ping from {first_host.name} to {last_host.name},\n"
        "    goes through all core switches\n"
    )
    packet_loss_pct = net.ping(hosts=[first_host, last_host], timeout=1)
    # Comparing floats (bad), but it's fine because an exact 0.0% packet loss is expected
    assert packet_loss_pct == 0.0, f"Packet loss occurred: {packet_loss_pct}%"


def connect_to_core_switch(switch_offset):
    """Sets common parameters for connecting to a switch on this topology"""
    return thrift_connect_standard("0.0.0.0", CORE_THRIFT_CORE_OFFSET + switch_offset)


def test_self():
    """
    The self-test's purpose is to test if we can run the network
    and if the network is working as expected.
    It also tests if our tooling is working as expected.
    """
    try:
        net = linear_topology()

        # sleep for a bit to let the network stabilize
        sleep(3)

        info("*** Running self tests\n")
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
        info("*** Self-test passed. Stopping network \n")
    finally:
        net.stop()


def test_addition():
    """
       Test if the network is protected against an addition attack

       An addition attack is when a new switch is added to the network between two existing switches,
       and the existing connections of surrounding switches = linear_topology()
    are not touched.
    """

    net = linear_topology()
    # net = linear_topology_with_attacker()
    try:

        # sleep for a bit to let the network stabilize
        sleep(3)

        info("*** Testing the baseline signatures\n")
        # ifaces = [
        #     iface
        #     for switch in net.switches
        #     for iface in switch.intfNames()
        #     if iface != "lo"
        # ]
        ifaces = [
            "e1-eth1",
            "s1-eth1",
            "e2-eth1",
            "s2-eth1",
            "e3-eth1",
            "s3-eth1",
            "e4-eth1",
            "s4-eth1",
            "e5-eth1",
            "s5-eth1",
            "e6-eth1",
            "s6-eth1",
            "e7-eth1",
            "s7-eth1",
            "e8-eth1",
            "s8-eth1",
            "e9-eth1",
            "s9-eth1",
            "e10-eth1",
            "s10-eth1",
            "e1-eth2",
            "e2-eth2",
            "e3-eth2",
            "e4-eth2",
            "e5-eth2",
            "e6-eth2",
            "e7-eth2",
            "e8-eth2",
            "e9-eth2",
            "e10-eth2",
            "s2-eth2",
            "s1-eth2",
            "s3-eth2",
            "s4-eth2",
            "s5-eth2",
            "s6-eth2",
            "s7-eth2",
            "s8-eth2",
            "s9-eth2",
            "s10-eth2",
            "s2-eth3",
            "s3-eth3",
            "s4-eth3",
            "s5-eth3",
            "s6-eth3",
            "s7-eth3",
            "s8-eth3",
            "s9-eth3",
            "e1-eth3",
        ]

        info(f"*** Sniffing on {ifaces}\n")

        sniff = AsyncSniffer(
            # All ifaces
            iface=ifaces,
            # filter=f"ether proto {POLKA_PROTO:#x}",
            filter="ether proto 0x1234",
            store=True,
        )

        info("*** Adding an attacker switch\n")

        # path = Path.dirname(Path.abspath(__file__))
        # config = f"{path}/polka/config/s{i}-commands.txt"
        # Add P4 switches (core)
        # attacker = net.addSwitch(
        #     "s555",
        #     netcfg=True,
        #     json=f"{path}/polka/polka-attacker.json",
        #     thriftport=CORE_THRIFT_CORE_OFFSET + 555,
        #     # switch_config=config,
        #     loglevel="debug",
        #     cls=P4Switch,
        # )

        # s3 = net.switches[2]
        # s4 = net.switches[3]

        # net.addLink(attacker, s3, bw=BW)
        # net.addLink(attacker, s4, bw=BW)

        # sleep for a bit to let the network stabilize
        # sleep(3)
        sniff.start()
        # Waits for the minimum amount for the sniffer to be setup and run
        while not hasattr(sniff, "stop_cb"):
            sleep(0.06)

        test_integrity(net)

        info("*** Stopping sniffing\n")
        pkts = sniff.stop()
        pkts.sort(key=lambda pkt: pkt.time)

        info("*** Checking the packets\n")
        BASE_DIGESTS = [
            # On the way to h10
            0x61E8D6E7,  # Seed, on ingress edge
            0xAE91434C,
            0x08C97F5F,
            0xEFF1AAD2,
            0x08040C89,
            0xAA99AE2E,
            0x7669685E,
            0x03E1E388,
            0x2138FFD3,
            0x1EF2CBBE,
            0x99C5FE05,
            # Reply, on the way back
            0x61E8D6E7,  # Seed, on ingress edge
            0xCFFABC9F,
            0x69409E70,
            0xF3E992E0,
            0x8DDE192B,
            0x92B098FA,
            0x1115A62C,
            0x41E1B5E0,
            0x227F0B72,
            0x82FC6346,
            0xD01E3E0F,
        ]
        half = len(BASE_DIGESTS) // 2
        # It is repeated because the ping is then initialized by h10 -> h1
        expected_digests = BASE_DIGESTS + BASE_DIGESTS[half:] + BASE_DIGESTS[:half]
        # Every row is duplicated because the capture captures the packet twice, once getting on the input and once getting on the output
        expected_digests = [digest for digest in expected_digests for _ in range(2)]

        # Using Python3.8, so can't use `zip(*iterables, strict=True)`

        count_error = False
        if len(pkts) != len(expected_digests):
            info(f"*** Expected {len(expected_digests)} packets, got {len(pkts)}")
            count_error = True

        for pkt, digest in zip(pkts, expected_digests):
            probe = pkt.getlayer(PolkaProbe)
            # info(f"{probe.fields=}\n")
            l_hash = probe.l_hash
            if l_hash == BASE_DIGESTS[0]:
                info("*** Comparing new ping\n")
            info(f"*** Comparing {l_hash:#0{10}X}, expects {digest:#0{10}X}\n")
            assert l_hash == digest, "Digest does not match"

        if count_error:
            raise AssertionError("Count error")

    finally:
        net.stop()


def test_detour():
    """
    Test if the network is protected against a detour attack.

    A detour attack is when a new switch is added to the network between two existing switches,
    concurring with an existing switch, with the same connections as the existing switch.
    """


def test_subtraction():
    """
    Test if the network is protected against a subtraction attack.

    A subtraction attack is when a switch is skipped in the route,
    and the packets are sent directly to the next switch in the route.
    """


def test_skipping():
    """
    Test if the network is protected against a skipping attack.

    A skipping attack is when a route skips the core entirely and goes directly to the edge.
    """


def run_network_tests():
    """
    Run a battery of tests on the network.
    The tests are specific to this topology and are hardcoded to test the specific topology.
    """

    info("*** Auto-testing network\n")
    try:
        # test_self()
        test_addition()
    except Exception as e:
        info(f"*** Test failed: {e}\n")
        raise e
    info("*** All tests passed.\n")


if __name__ == "__main__":
    setLogLevel("info")
    run_network_tests()

    # info("*** Running CLI\n")
    # net = linear_topology()
    # CLI(net)
    # info("*** Stopping network\n")
    # net.stop()
