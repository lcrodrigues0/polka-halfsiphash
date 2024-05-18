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

from mininet.log import setLogLevel, info
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
            thriftport=50000 + int(i),
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
            thriftport=50100 + int(i),
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

    info("*** Auto-testing network\n")
    run_network_tests(net)

    info("*** All tests passed.\n")

    info("*** Running CLI\n")
    CLI(net)

    os.system("pkill -9 -f 'xterm'")

    info("*** Stopping network\n")
    net.stop()


def test_integrity(net):
    """
    Test the integrity of the network, this is to be used in a suite of tests
    """
    first_host = net.hosts[0]
    last_host = net.hosts[-2]
    print(
        (
            "*** Testing network integrity\n",
            f"    a ping from {first_host.name} to {last_host.name},\n"
            "    goes through all switches",
        )
    )
    packet_loss_pct = net.ping([first_host, last_host], timeout=1)
    assert packet_loss_pct == 0.0, f"Packet loss: {packet_loss_pct}%"


def run_network_tests(net):
    """
    Run the tests in the network
    """

    # sleep for 5 seconds to let the network stabilize
    sleep(5)

    print("*** Running tests")
    # Test before running the tests
    test_integrity(net)

    # Break the connection
    print("*** Breaking the polka routing on s3")
    print(f"{net.ipBase=}")
    print(f"{net.host=}")
    s3 = thrift_connect_standard(net.ipBase[:-2], 50003)
    set_crc_parameters_common(s3, "calc 0x0000 0x0 0x0 false false")

    try:
        # Test after breaking the connection
        test_integrity(net)
    except AssertionError:
        # Test should fail
        print("*** Test failed as expected")
    else:
        # Test should fail
        raise AssertionError("Test should have failed")

    # Restore the connection
    print("*** Restoring the polka routing on s3")
    set_crc_parameters_common(s3, "calc 0x0039 0x0 0x0 false false")

    # Test after restoring the connection
    test_integrity(net)


if __name__ == "__main__":
    setLogLevel("info")
    linear_topology()
