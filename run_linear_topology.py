#!/usr/bin/python3
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

# https://mininet.org/api/hierarchy.html
from mininet.log import setLogLevel, info, debug
from mn_wifi.cli import CLI  # type: ignore assumes import exists, it's from p4-utils

import script.tester as tester
import script.connect_api as connect_api
from script.topo import linear_topology


def run_network_tests():
    """
    Run a battery of tests on the network.
    The tests are specific to this topology and are hardcoded to test the specific topology.
    """

    info("*** Auto-testing network\n")
    try:
        # tester.self()
        tester.addition()
        tester.skipping()
        tester.detour()
        tester.outoforder()
    except Exception as e:
        info(f"*** Test failed: {e}\n")
        raise e
    info("*** ✅ All tests passed.\n")


if __name__ == "__main__":
    setLogLevel("info")
    # run_network_tests()
    # tester.collect_hashes()

    connect_api.connect_api()
    # connect_api.get_hashes_hops()

    # info("*** Running CLI\n")
    # net = linear_topology()
    # CLI(net)
    # info("*** Stopping network\n")
    # net.stop()
