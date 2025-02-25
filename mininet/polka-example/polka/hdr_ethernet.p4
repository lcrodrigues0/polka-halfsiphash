/*
 * Copyright 2019-present GEANT RARE project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed On an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _ETHERNET_P4_
#define _ETHERNET_P4_

#include "def_types.p4"

/*
 * Ethernet header: as a header type, order matters
 */
header ethernet_t {
    mac_addr_t  dst_mac_addr;
    mac_addr_t  src_mac_addr;
    ethertype_t ethertype;
}

#endif	// _ETHERNET_P4_
