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

from tests.test_detour import test_detour
from utils.check_digest import BASE_DIGESTS
from utils.sniff import start_sniffing
from linear_topology import Polka, PolkaProbe, linear_topology, set_seed_e1, set_seed_e10
from utils.call_api import call_deploy_flow_contract, call_log_probe, call_set_ref_sig
from tests.flow_test import flow_test, process_pkts

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
        
        sniff = start_sniffing(net)

        n_pkts = 3
        flow_test(net, "0", "h1", "h10", n_pkts)

        info("\n*** Stopping sniffing\n")
        pkts = sniff.stop()

        (first, last) = process_pkts(pkts, n_pkts)

        i = 0
        for pkt in last:
            probe = pkt.getlayer(PolkaProbe)
            polka = pkt.getlayer(Polka)

            print(f"{i} - {polka.ttl:#0{6}x} -> {probe.l_hash:#0{10}x}")
            i += 1
         
        flowId = 0
        call_deploy_flow_contract(flowId, first[0])
        for i in range(0, n_pkts):
            call_set_ref_sig(flowId, first[i])
            call_log_probe(flowId, last[i])

        info("\n*** Hashes collected ***\n")


    finally:
        net.stop()


    info("*** ✅ Run finished.\n")

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

    # info("*** Running CLI\n")
    # net = linear_topology()
    # CLI(net)
    # info("*** Stopping network\n")
    # net.stop()