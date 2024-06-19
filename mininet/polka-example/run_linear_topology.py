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
from typing import Iterable, Callable, TypeVar
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
LINK_SPEED = 10

CORE_THRIFT_CORE_OFFSET = 50000
EDGE_THRIFT_CORE_OFFSET = 50100

POLKA_PROTO = 0x1234
PROBE_VERSION = 0xF1

bind_layers(Ether, Polka, type=POLKA_PROTO)
bind_layers(Polka, PolkaProbe, version=PROBE_VERSION)
bind_layers(PolkaProbe, Ipv4)


def linear_topology_add_hosts(net: Mininet_wifi):
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


def linear_topology_add_switches(net: Mininet_wifi):
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


def linear_topology(start=True) -> Mininet_wifi:
    "Create a network."
    net = Mininet_wifi()
    try:
        # linkopts = dict()
        net, hosts = linear_topology_add_hosts(net)
        net, cores, edges = linear_topology_add_switches(net)

        info("*** Creating links\n")
        for i in range(0, N_SWITCHES):
            net.addLink(hosts[i], edges[i], bw=LINK_SPEED)
            net.addLink(edges[i], cores[i], bw=LINK_SPEED)

        last_switch = None

        for i in range(0, N_SWITCHES):
            switch = cores[i]

            if last_switch:
                net.addLink(last_switch, switch, bw=LINK_SPEED)
            last_switch = switch

        # host 11
        net.addLink(hosts[-1], edges[0], bw=LINK_SPEED)

        if start:
            info("*** Starting network\n")
            net.start()
            net.staticArp()

        # disabling offload for rx and tx on each host interface
        for host in hosts:
            host.cmd(f"ethtool --offload {host.name}-eth0 rx off tx off")

        return net
    except Exception as e:
        net.stop()
        raise e


def add_config_e1(net: Mininet_wifi, command: str) -> Mininet_wifi:
    """Net needs to be stopped"""
    e1 = net.get("e1")
    s1 = net.get("s1")
    links = net.delLinkBetween(e1, s1, allLinks=True)
    assert (
        len(links) == 1
    ), f"❌ Expected 1 link to be removed between e1 and s1. Removed {len(links)} links."
    h1 = net.get("h1")
    links = net.delLinkBetween(e1, h1, allLinks=True)
    assert (
        len(links) == 1
    ), f"❌ Expected 1 link to be removed between e1 and h1. Removed {len(links)} links."
    h11 = net.get("h11")
    links = net.delLinkBetween(e1, h11, allLinks=True)
    assert (
        len(links) == 1
    ), f"❌ Expected 1 link to be removed between e1 and h11. Removed {len(links)} links."
    e1.stop()
    net.delNode(e1)

    # read the network configuration
    path = Path.dirname(Path.abspath(__file__))
    directory = f"{path}/polka/config"
    base_commands = f"{directory}/e1-commands.txt"
    with open(base_commands, "r") as f:
        commands = f.read()
    commands += command

    # Save the new configuration
    savepath = f"{directory}/e1-commands-overwritten.txt"
    with open(savepath, "w") as f:
        f.write(commands)

    # add P4 switches (edge)
    e1 = net.addSwitch(
        "e1",
        netcfg=True,
        json=f"{path}/polka/polka-edge.json",
        thriftport=EDGE_THRIFT_CORE_OFFSET + 1,
        switch_config=savepath,
        loglevel="debug",
        cls=P4Switch,
    )

    # Link as before
    net.addLink(e1, h1, port1=1, port2=0, bw=LINK_SPEED)
    net.addLink(e1, h11, port1=0, port2=0, bw=LINK_SPEED)
    net.addLink(e1, s1, port1=2, port2=1, bw=LINK_SPEED)

    return net


def add_config_e10(net: Mininet_wifi, command: str) -> Mininet_wifi:
    """Net needs to be stopped"""
    e10 = net.get("e10")
    s10 = net.get("s10")
    links = net.delLinkBetween(e10, s10, allLinks=True)
    assert (
        len(links) == 1
    ), f"❌ Expected 1 link to be removed between e10 and s10. Removed {len(links)} links."
    h10 = net.get("h10")
    links = net.delLinkBetween(e10, h10, allLinks=True)
    assert (
        len(links) == 1
    ), f"❌ Expected 1 link to be removed between e10 and h10. Removed {len(links)} links."
    e10.stop()
    net.delNode(e10)

    # read the network configuration
    path = Path.dirname(Path.abspath(__file__))
    directory = f"{path}/polka/config"
    base_commands = f"{directory}/e10-commands.txt"
    with open(base_commands, "r") as f:
        commands = f.read()
    commands += command

    # Save the new configuration
    savepath = f"{directory}/e10-commands-overwritten.txt"
    with open(savepath, "w") as f:
        f.write(commands)

    # add P4 switches (edge)
    e10 = net.addSwitch(
        "e10",
        netcfg=True,
        json=f"{path}/polka/polka-edge.json",
        thriftport=EDGE_THRIFT_CORE_OFFSET + 10,
        switch_config=savepath,
        loglevel="debug",
        cls=P4Switch,
    )

    # Link as before
    net.addLink(e10, h10, port1=1, port2=0, bw=LINK_SPEED)
    net.addLink(e10, s10, port1=2, port2=1, bw=LINK_SPEED)

    return net


def set_seed_e1(net: Mininet_wifi, seed: int) -> Mininet_wifi:
    return add_config_e1(net, f"table_add config seed 0 => {seed}")


def set_seed_e10(net: Mininet_wifi, seed: int) -> Mininet_wifi:
    return add_config_e10(net, f"table_add config seed 0 => {seed}")


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


def test_integrity(net: Mininet_wifi):
    """
    Test the integrity of the network, this is to be used in a suite of tests
    """

    def hunt_host(net: Mininet_wifi, name: str):
        for host in net.hosts:
            if host.name == name:
                return host
        return None

    first_host = hunt_host(net, "h1")
    assert first_host is not None, "Host h1 not found"
    last_host = hunt_host(
        net, "h10"
    )  # h11 is right beside h1, so wouldn't traverse all switches
    assert last_host is not None, "Host h10 not found"

    info(
        "*** Testing network integrity\n"
        f"    a ping from {first_host.name} to {last_host.name},\n"
        "    goes through all core switches.\n"
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


# H1 -> H10
BASE_DIGESTS = {
    # On the way to h10
    "h1-h10": {
        # Seed, on ingress edge
        0x61E8D6E7: [
            0x61E8D6E7,
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
        ],
        0xDEADBEEF: [
            0xDEADBEEF,
            0x3E2E3B36,
            0x2CBD4C0A,
            0x7C33927C,
            0x132B32F9,
            0x0F50152C,
            0x7B9D3AF9,
            0x8379E9C4,
            0xBAE44591,
            0x76D807C1,
            0xF5781630,
        ],
        0xBADDC0DE: [
            0xBADDC0DE,
            0x3EF96770,
            0x2DCA9942,
            0x11797334,
            0x98081E3E,
            0x3332E012,
            0x22996AFD,
            0x8FA3987D,
            0xF4B50950,
            0xD0C29E67,
            0x13FF41C1,
        ],
        0xABADCAFE: [
            0xABADCAFE,
            0x432CF798,
            0xE04DF688,
            0xE8F0142C,
            0xB452022A,
            0x4450D2D2,
            0xE9367B57,
            0x991182C1,
            0x35E72E11,
            0xAA152EB9,
            0x1A1573E7,
        ],
    },
    # Reply, on the way back
    "h10-h1": {
        # Seed, ON INGRESS EDGE
        0x61E8D6E7: [
            0x61E8D6E7,
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
        ],
        0xDEADBEEF: [
            0xDEADBEEF,
            0x5F45C4E5,
            0x4D34AD25,
            0x602BAA4E,
            0x96F1275B,
            0x377923F8,
            0x1CE1F48B,
            0xC179BFAC,
            0xB9A3B130,
            0xEAD6AF39,
            0xBCA3D63A,
        ],
        0xBADDC0DE: [
            0xBADDC0DE,
            0x5F9298A3,
            0x4C43786D,
            0X0D614B06,
            0x1DD20B9C,
            0x0B1BD6C6,
            0x45E5A48F,
            0xCDA3CE15,
            0xF7F2FDF1,
            0x4CCC369F,
            0x5A2481CB,
        ],
        0xABADCAFE: [
            0xABADCAFE,
            0x2247084B,
            0x81C417A7,
            0xF4E82C1E,
            0x31881788,
            0x7C79E406,
            0x8E4AB525,
            0xDB11D4A9,
            0x36A0DAB0,
            0x361B8641,
            0x53CEB3ED,
        ],
    },
}

T = TypeVar("T")


def check_digest(pkts: Iterable[Packet], seed_src: int, seed_dst: int):
    """
    Check if the packets have the expected digests
    """
    # for pkt in pkts:
    #     print(f"{pkt.getlayer(PolkaProbe).l_hash:#0{10}x}, {pkt.getlayer(PolkaProbe).timestamp:#0{10}x}")

    going = BASE_DIGESTS["h1-h10"][seed_src]
    reply = BASE_DIGESTS["h10-h1"][seed_dst]

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
        if pkt.getlayer(PolkaProbe).l_hash in (seed_src, seed_dst):
            marker_flag = not marker_flag
        if marker_flag:
            routes.append([pkt])
        else:
            routes[-1].append(pkt)
    assert (
        len(routes) == 4
    ), f"❌ Expected 4 routes (send, reply, send back, reply back). Got {len(routes)}"

    # Using Python3.8, so can't use `zip(*iterables, strict=True)`

    info("*** Checking collected packets\n")
    for route, expected_digests in zip(routes, (going, reply, reply, going)):
        info("*** 🔍 Tracing new route\n")
        for pkt, expected_digest in zip(route, expected_digests):
            polka = pkt.getlayer(Polka)
            probe = pkt.getlayer(PolkaProbe)
            l_hash = probe.l_hash
            info(
                f"*** Comparing {l_hash:#0{10}x}, expects {expected_digest:#0{10}x} "
                f"on node {polka.ttl:#0{6}x}:{pkt.sniffed_on} "
            )
            if l_hash == expected_digest:
                info("✅ ok\n")
            else:
                info("❌ Digest does not match\n")

        if len(route) != len(expected_digests):
            info(
                f"*** ❌ Route length does not match expected. Expected {len(expected_digests)}, got {len(route)}\n"
            )
            if len(route) < len(expected_digests):
                for digest in expected_digests[len(route) :]:
                    info(f"*** Missing digest {digest:#0{10}x}\n")
            else:
                info("*** ❌ Leftover packets:\n")
                for pkt in route[len(expected_digests) :]:
                    polka = pkt.getlayer(Polka)
                    probe = pkt.getlayer(PolkaProbe)
                    info(
                        f"*** {probe.l_hash:#0{10}x} on node {polka.ttl:#0{6}x}:{pkt.sniffed_on}\n"
                    )


def all_ifaces(net: Mininet_wifi):
    return [
        iface
        for switch in net.switches
        for iface in switch.intfNames()
        if iface != "lo"
    ]


def start_sniffing(net: Mininet_wifi):
    info(f"*** 👃 Sniffing on {all_ifaces(net)}\n")

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


def run_network_tests():
    """
    Run a battery of tests on the network.
    The tests are specific to this topology and are hardcoded to test the specific topology.
    """

    info("*** Auto-testing network\n")
    try:
        # test_self()
        # test_addition()
        # test_skipping()
        test_detour()
    except Exception as e:
        info(f"*** Test failed: {e}\n")
        raise e
    info("*** ✅ All tests passed.\n")


if __name__ == "__main__":
    setLogLevel("info")
    run_network_tests()

    # info("*** Running CLI\n")
    # net = linear_topology()
    # CLI(net)
    # info("*** Stopping network\n")
    # net.stop()
