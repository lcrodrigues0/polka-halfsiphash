from os import path as Path
from typing import Callable

from mininet.log import info
from mn_wifi.net import Mininet_wifi
from mn_wifi.bmv2 import P4Switch

from polka_controller.controller_polka import (
    thrift_connect_standard,
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


def connect_to_core_switch(switch_offset):
    """Sets common parameters for connecting to a switch on this topology"""
    return thrift_connect_standard("0.0.0.0", CORE_THRIFT_CORE_OFFSET + switch_offset)


def all_ifaces(net: Mininet_wifi):
    return [
        iface
        for switch in net.switches
        for iface in switch.intfNames()
        if iface != "lo"
    ]