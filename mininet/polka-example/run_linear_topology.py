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
from time import sleep
from mininet.log import setLogLevel, info
from os import getcwd
from mn_wifi.bmv2 import P4Switch
from time import sleep


from tests.test_detour import test_detour
from utils.sniff import start_sniffing
from linear_topology import linear_topology, set_seed_e1, set_seed_e10, CORE_THRIFT_CORE_OFFSET, LINK_SPEED
from utils.call_api import call_deploy_flow_contract, call_log_probe, call_set_ref_sig
from tests.flow_test import flow_test, process_pkts, print_pkts


def collect_hashes():
    """
    Collect the hashes from the network
    """

    info("*** Starting run for collecting hash and intermediaries\n")

    net = linear_topology(start=False)    
    try:
        net = set_seed_e1(net, 0xABADCAFE)
        net = set_seed_e10(net, 0xBADDC0DE)

        net.start()
        net.staticArp()

        # sleep for a bit to let the network stabilize
        sleep(3)
        
        paths = [["h1", "h10"], ["h10", "h1"]]
        for i in range(0, 2):
            print(f"\n-------- Starting test {i + 1}: {paths[i][0]} to {paths[i][1]}\n")

            print("Enter the number of packages: ", end="")
            n_pkts = int(input())
            print()

            # Start Sniffing
            sniff = start_sniffing(net)

            # Ping 
            flow_test(net, paths[i][0], paths[i][1], n_pkts)

            # Stop sniffing
            info("\n*** Stopping sniffing\n")
            pkts = sniff.stop()

            # Selecting packets 
            (first, last) = process_pkts(pkts, n_pkts)

            # Printing selected packets
            # print_pkts(first)
            # print_pkts(last)
            
            # Registering Flow
            flowId = i
            call_deploy_flow_contract(flowId, first[0])

            # Registering probes
            for j in range(0, n_pkts):
                print(f"\n*** Probe {j}:")
                call_set_ref_sig(flowId, first[j], paths[i])
                call_log_probe(flowId, last[j])
            
            print(f"\n-------- Test {i + 1} done")

        info("\n*** Hashes collected ***\n")


    finally:
        net.stop()


    info("*** ✅ Run finished.\n")


def test_flow_detour():
    """
    Test if the network is protected against a detour attack.

    A detour attack is when a new switch is added to the network between two existing switches,
    concurring with an existing switch, with the same connections as the existing switch.
    """

    net = linear_topology(start=False)

    try:
        prev_sw, skipped, next_sw = net.switches[4:7]
        info(f"\n\n*** Replacing {prev_sw.name}'s links with compromised route\n")

        links = net.delLinkBetween(prev_sw, skipped, allLinks=True)
        assert (
            len(links) == 1
        ), f"❌ Expected 1 link to be removed between {prev_sw.name} and {skipped.name}"

        links = net.delLinkBetween(next_sw, skipped, allLinks=True)
        assert (
            len(links) == 1
        ), f"❌ Expected 1 link to be removed between {skipped.name} and {next_sw.name}"

        info("\n*** Adding attacker\n")
        
        polka_json_dir = f"{getcwd()}/polka/"

        attacker = net.addSwitch(
            "s555",
            netcfg=True,
            json=polka_json_dir + "polka-attacker.json",
            thriftport=CORE_THRIFT_CORE_OFFSET + 555,
            loglevel="debug",
            cls=P4Switch,
        )

        info("\n*** Linking attacker\n")
        
        # Taking the "default" port #3 which route from s4 -> s5 -> s6 should pass through on s5
        link = net.addLink(prev_sw, attacker, port1=3, port2=0, bw=LINK_SPEED)
        info(f"*** Created link {link}")
        
        link = net.addLink(attacker, next_sw, port1=1, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {link}")
        
        # relink skipped sw
        link = net.addLink(prev_sw, skipped, port1=4, port2=2, bw=LINK_SPEED)
        info(f"*** Created link {link}")
        
        link = net.addLink(skipped, next_sw, port1=3, port2=4, bw=LINK_SPEED)
        info(f"*** Created link {link}")

        net = set_seed_e1(net, 0xBADDC0DE)
        net = set_seed_e10(net, 0xDEADBEEF)

        net.start()
        net.staticArp()

        # sleep for a bit to let the network stabilize
        sleep(3)

        print(f"\n-------- Starting test detour\n")

        path = ["h1", "h10"]
        print("Enter the number of packages: ", end="")
        n_pkts = int(input())
        print()

        # Start Sniffing
        sniff = start_sniffing(net)

        # Ping 
        flow_test(net, path[0], path[1], n_pkts)

        # Stop sniffing
        info("\n*** Stopping sniffing\n")
        pkts = sniff.stop()

        # Selecting packets 
        (first, last) = process_pkts(pkts, n_pkts)

        # Printing selected packets
        # print_pkts(first)
        # print_pkts(last)
        
        # Registering Flow
        flowId = 3
        call_deploy_flow_contract(flowId, first[0])

        # Registering probes
        for j in range(0, n_pkts):
            print(f"\n*** Probe {j}:")
            call_set_ref_sig(flowId, first[j], path)
            call_log_probe(flowId, last[j])

        info("\n*** Detour test done ***\n\n")

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
    # run_network_tests()

    collect_hashes()

    print("\nRun test detour? ", end="")
    
    if input() == 'y':
        test_flow_detour()