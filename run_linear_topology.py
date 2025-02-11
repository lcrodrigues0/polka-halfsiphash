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
from os import path as Path
from typing import Iterable, Callable, TypeVar
from time import sleep
import urllib.request

# https://mininet.org/api/hierarchy.html
from mininet.log import setLogLevel, info, debug
from mn_wifi.cli import CLI  # type: ignore assumes import exists, it's from p4-utils
from mn_wifi.net import Mininet  # type: ignore assumes import exists, it's from p4-utils
from mn_wifi.bmv2 import P4Switch  # type: ignore assumes import exists, it's from p4-utils

import urllib, json

from script.thrift import (
    thrift_connect_standard,
    set_crc_parameters_common,
)
from script.topo import linear_topology, set_seed_e1, set_seed_e10
from script.scapy import Polka, PolkaProbe
import script.test as test


def run_network_tests():
    """
    Run a battery of tests on the network.
    The tests are specific to this topology and are hardcoded to test the specific topology.
    """

    info("*** Auto-testing network\n")
    try:
        test.self()
        test.addition()
        test.skipping()
        test.detour()
    except Exception as e:
        info(f"*** Test failed: {e}\n")
        raise e
    info("*** ✅ All tests passed.\n")


if __name__ == "__main__":
    setLogLevel("info")
    run_network_tests()
    # collect_siphash()

    # info("*** Running CLI\n")
    # net = linear_topology()
    # CLI(net)
    # info("*** Stopping network\n")
    # net.stop()
