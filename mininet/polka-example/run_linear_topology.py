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

import urllib.request
import json

from tests.test_detour import test_detour
from tests.test_integrity import test_integrity
from utils.check_digest import BASE_DIGESTS
from utils.sniff import start_sniffing
from linear_topology import Polka, PolkaProbe, linear_topology, set_seed_e1, set_seed_e10

ENDPOINT_URL = "http://localhost:5000/"


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


def call_deploy_flow_contract():
    data_dct = {
        "flowId": "0",
        "routeId": "1",
        "edgeAddr": "0x3BAA3CbF7AF166AE1D583395eE38b694005b9C04"
    }

    req = urllib.request.Request(
        ENDPOINT_URL + "/deployFlowContract",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req)
    print(res.read())

def call_set_ref_sig(pkt):
    polka_pkt = pkt.getlayer(Polka)
    probe_pkt = pkt.getlayer(PolkaProbe)

    data_dct = {
        "flowId": "0",
        "routeId": str(polka_pkt.route_id),
        "timestamp": str(probe_pkt.timestamp),
        "lightMultSig": str(hex(BASE_DIGESTS["h1-h10"][probe_pkt.l_hash][10])),
    }

    print(hex(probe_pkt.l_hash))
    print(hex(BASE_DIGESTS["h1-h10"][probe_pkt.l_hash][10]))

    req = urllib.request.Request(
        ENDPOINT_URL + "setRefSig",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req)
    print(res.read())

def call_log_probe(pkt):
    polka_pkt = pkt.getlayer(Polka)
    probe_pkt = pkt.getlayer(PolkaProbe)

    data_dct = {
        "flowId": "0",
        "routeId": str(polka_pkt.route_id),
        "timestamp": str(probe_pkt.timestamp),
        "lightMultSig": str(hex(probe_pkt.l_hash)),   
    }

    print(hex(probe_pkt.l_hash))

    req = urllib.request.Request(
        ENDPOINT_URL + "logProbe",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req)
    print(res.read())

def collect_siphash():
    """
    Collect the SIPHashes (all intermediary) from the network
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

        test_integrity(net)

        info("*** Stopping sniffing\n")
        pkts = sniff.stop()
        pkts.sort(key=lambda pkt: pkt.time)

        for pkt in pkts:
            probe = pkt.getlayer(PolkaProbe)
            polka = pkt.getlayer(Polka)

            print(f"{polka.ttl:#0{6}x} -> {probe.l_hash:#0{10}x}")


        # Sending the seed can only be done after this, since pkts can arrive out of order
        # So the pkt has already completed the request.
        call_deploy_flow_contract()
        call_set_ref_sig(pkts[0])
        call_log_probe(pkts[-1])

        info("*** Hashes collected ***\n")


    finally:
        net.stop()


    info("*** ✅ Run finished.\n")

if __name__ == "__main__":
    setLogLevel("info")
    # run_network_tests()

    collect_siphash()

    # info("*** Running CLI\n")
    # net = linear_topology()
    # CLI(net)
    # info("*** Stopping network\n")
    # net.stop()
