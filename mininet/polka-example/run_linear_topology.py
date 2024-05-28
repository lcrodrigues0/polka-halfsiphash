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
import os
from time import sleep

from mininet.log import setLogLevel, info, debug
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.bmv2 import P4Switch


from polka_controller.controller_polka import (
    thrift_connect_standard,
    set_crc_parameters_common,
)

# from mininet.term import makeTerm
# from mininet.node import RemoteController

N_SWITCHES = 10
BW = 10

CORE_THRIFT_CORE_OFFSET = 50000
EDGE_THRIFT_CORE_OFFSET = 50100


def linear_topology():
    "Create a network."
    net = Mininet_wifi()

    # linkopts = dict()
    switches = []
    edges = []
    hosts = []

    info("*** Adding hosts\n")
    for i in range(1, N_SWITCHES + 1):
        ip = f"10.0.{i}.{i}"
        mac = f"00:00:00:00:{i:02x}:{i:02x}"
        host = net.addHost(f"h{i}", ip=ip, mac=mac)
        hosts.append(host)

    # host 11
    i_1, i_2 = 1, 11
    ip = f"10.0.{i_1}.{i_2}"
    mac = f"00:00:00:00:{i_1:02x}:{i_2:02x}"
    host = net.addHost("h11", ip=ip, mac=mac)
    hosts.append(host)

    info("*** Adding P4Switches (core)\n")
    for i in range(1, N_SWITCHES + 1):
        # read the network configuration
        path = os.path.dirname(os.path.abspath(__file__))
        json_file = f"{path}/polka/polka-core.json"
        config = f"{path}/polka/config/s{i}-commands.txt"
        # Add P4 switches (core)
        switch = net.addSwitch(
            f"s{i}",
            netcfg=True,
            json=json_file,
            thriftport=CORE_THRIFT_CORE_OFFSET + int(i),
            switch_config=config,
            loglevel="debug",
            cls=P4Switch,
        )
        switches.append(switch)

    info("*** Adding P4Switches (edge)\n")
    for i in range(1, N_SWITCHES + 1):
        # read the network configuration
        path = os.path.dirname(os.path.abspath(__file__))
        json_file = f"{path}/polka/polka-edge.json"
        config = f"{path}/polka/config/e{i}-commands.txt"
        # add P4 switches (core)
        edge = net.addSwitch(
            f"e{i}",
            netcfg=True,
            json=json_file,
            thriftport=EDGE_THRIFT_CORE_OFFSET + int(i),
            switch_config=config,
            loglevel="debug",
            cls=P4Switch,
        )
        edges.append(edge)

    info("*** Creating links\n")
    for i in range(0, N_SWITCHES):
        net.addLink(hosts[i], edges[i], bw=BW)
        net.addLink(edges[i], switches[i], bw=BW)

    last_switch = None

    for i in range(0, N_SWITCHES):
        switch = switches[i]

        if last_switch:
            net.addLink(last_switch, switch, bw=BW)
        last_switch = switch

    # host 11
    net.addLink(hosts[10], edges[0], bw=BW)

    info("*** Starting network\n")
    net.start()
    net.staticArp()

    # disabling offload for rx and tx on each host interface
    for host in hosts:
        host.cmd(f"ethtool --offload {host.name}-eth0 rx off tx off")

    return net


def test_integrity(net):
    """
    Test the integrity of the network, this is to be used in a suite of tests
    """
    first_host = net.hosts[0]
    last_host = net.hosts[-2]
    print(
        "*** Testing network integrity\n"
        f"    a ping from {first_host.name} to {last_host.name},\n"
        "    goes through all core switches"
    )
    packet_loss_pct = net.ping(hosts=[first_host, last_host], timeout=1)
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

    # sleep for a bit to let the network stabilize
    sleep(5)

    info("*** Running tests\n")
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
        raise AssertionError("Test should have failed")

    info("*** Restoring the polka routing on s3\n")
    set_crc_parameters_common(s3, "calc 0x0039 0x0 0x0 false false")

    test_integrity(net)
    info("*** Self-test passed. Stopping network \n")
    net.stop()


def test_addition():
    """
    Test if the network is protected against an addition attack

    An addition attack is when a new switch is added to the network between two existing switches,
    and the existing connections of surrounding switches = linear_topology()
 are not touched.
    """

    net = linear_topology()

    info("*** Adding an attacker switch\n")

    path = os.path.dirname(os.path.abspath(__file__))
    json_file = f"{path}/polka/polka-core.json"
    # config = f"{path}/polka/config/s{i}-commands.txt"
    # Add P4 switches (core)
    attacker = net.addSwitch(
        "s555",
        netcfg=True,
        json=json_file,
        thriftport=CORE_THRIFT_CORE_OFFSET + 555,
        # switch_config=config,
        loglevel="debug",
        cls=P4Switch,
    )

    s3 = net.switches[2]
    s4 = net.switches[3]

    net.addLink(attacker, s3, bw=BW)
    net.addLink(attacker, s4, bw=BW)

    # sleep for a bit to let the network stabilize
    sleep(5)

    info("*** Running tests\n")
    test_integrity(net)
    net.stop()


def test_detour():
    """
    Test if the network is protected against a detour attack.

    A detour attack is when a new switch is added to the network between two existing switches,
    concurring with an existing switch, with the same connections as the existing switch.
    """

    net = linear_topology()

    info("*** Adding an attacker switch\n")

    path = os.path.dirname(os.path.abspath(__file__))
    json_file = f"{path}/polka/polka-core.json"
    # config = f"{path}/polka/config/s{i}-commands.txt"
    # Add P4 switches (core)
    attacker = net.addSwitch(
        "s555",
        netcfg=True,
        json=json_file,
        thriftport=CORE_THRIFT_CORE_OFFSET + 555,
        # switch_config=config,
        loglevel="debug",
        cls=P4Switch,
    )

    s3 = net.switches[2]
    s5 = net.switches[4]

    net.addLink(attacker, s3, bw=BW)
    net.addLink(attacker, s5, bw=BW)

    # sleep for a bit to let the network stabilize
    sleep(5)

    info("*** Running tests\n")
    test_integrity(net)
    net.stop()


def test_subtraction():
    """
    Test if the network is protected against a subtraction attack.

    A subtraction attack is when a switch is skipped in the route,
    and the packets are sent directly to the next switch in the route.
    """

    net = linear_topology()



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
    test_self()
    info("*** All tests passed.\n")


if __name__ == "__main__":
    setLogLevel("info")
    run_network_tests()

    info("*** Running CLI\n")
    net = linear_topology()
    CLI(net)
    info("*** Stopping network\n")
    net.stop()
