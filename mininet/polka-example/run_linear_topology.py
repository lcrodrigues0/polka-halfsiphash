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
from threading import Thread

from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.bmv2 import P4Switch

# from mininet.term import makeTerm
# from mininet.node import RemoteController

N_SWITCHES = 10
BW = 10

net = None


def linear_topology(callback: callable = lambda: None):
    "Create a network."
    global net
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

    info("*** Signaling that network setup is complete\n")
    callback(hosts)

    info("*** Running CLI\n")
    CLI(net)

    os.system("pkill -9 -f 'xterm'")

    info("*** Stopping network\n")
    net.stop()


def test_integrity(net, hosts):
    """
    Test the integrity of the network, this is to be used in a suite of tests
    """
    print("*** Testing network integrity")
    packet_loss_pct = net.ping([hosts[0], hosts[-2]])
    assert packet_loss_pct == 0.0, f"Packet loss: {packet_loss_pct}%"


def run_network_tests(hosts):
    """
    Run the tests in the network
    """
    global net
    # sleep for 5 seconds to let the network stabilize
    from time import sleep

    sleep(5)
    # Test before running the tests
    test_integrity(net, hosts)

    assert False, "Tests failed"


def run_network_tests_callback(hosts):
    """
    Create a thread to run the tests and instantly return to not block the CLI
    """
    t = Thread(target=run_network_tests, args=(hosts,))
    t.start()
    return


if __name__ == "__main__":
    setLogLevel("info")
    linear_topology(run_network_tests_callback)
