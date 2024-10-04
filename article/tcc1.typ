#import "@preview/fletcher:0.5.1" as fletcher: diagram, node, edge, shapes
#import "@preview/codly:1.0.0": *

#set page(paper: "a4")
#set text(font: "New Computer Modern", size: 11pt)
#set par(justify: true)
#set heading(numbering: "1.")
#let appendix(body) = {
  set heading(numbering: "A.1.", supplement: [Appendix])
  counter(heading).update(0)
  body
}
#show link: it => text(blue, underline(it))
#show: codly-init.with()
#codly(languages: (
  p4: (
      name: "p4",
      // icon: text(font: "tabler-icons", "\u{fa53}"),
      // color: rgb("#CE412B")
    ),
))

#show "CRC32": $"CRC"_32$
#show "Polka": "PolKA"
#show "polka": "PolKA"

#let midsection(it) = align(center, text(size: 1.1em, weight: "bold", it))

#include("anteprojeto.typ")

//  Reset heading counter
#counter(heading).update(0)
#pagebreak()

#let title = [An Implementation of Route Probing and Validation on PolKA]

#midsection(text(size: 1.5em, title))

#{
  let UFESsym = sym.dagger
  let IFESsym = sym.dagger.double
  let UFES(it) = box()[#it#UFESsym]
  let IFES(it) = box()[#it#IFESsym]

  let authors_UFES = (
    "Henrique Coutinho Layber",
    "Roberta Lima Gomes",
    "Magnos Martinello",
    "Vitor B. Bonella",
  )
  let authors_IFES = ("Everson S. Borges",)
  let authors_both = ("Rafael Guimarães",)
  let authors_sep = ", "

  set par(justify: false)
  set align(center)

  [
    #{
      (
        authors_UFES.map(UFES).join(authors_sep),
        authors_IFES.map(IFES).join(authors_sep),
        authors_both.map(UFES).map(IFES).join(authors_sep),
      ).join(authors_sep)
    }

    #UFESsym\Department of Informatics, Federal University of Espírito Santo \
    #IFESsym\Department of Informatics, Federal Institute of Education Science and Technology of Espírito Santo
  ]
}

#midsection[Abstract]

This paper presents an implementation of a route probing and validation mechanism for the source routing protocol PolKA. The mechanism is based on a composition of checksum functions on stateless core switches, which allows a trusted party to verify if a packet traversed the network along the path defined by the source.

#midsection[Keywords]

#{
  let keyword_sep = [; ]
  let keywords = (
    "Verifiable Routing",
    "Path Verification",
    "Proof-of-transit",
    "In-networking Programming",
  )
  text(weight: "bold", keywords.join(keyword_sep))
}

= Introduction

Ever since Source Routing (SR) was proposed, there has been a need to ensure that packets traverse the network along the paths selected by the source, not only for security reasons but also to ensure that the network is functioning correctly and correctly configured. This is particularly important in the context of Software-Defined Networking (SDN), where the control plane can select paths based on a variety of criteria.

In this paper, we propose a new P4@p4 implementation for a new protocol layer for PolKA@polka, able to do validate the actual route used for a packet, and is available on GitHub#footnote[https://github.com/Henriquelay/polka-halfsiphash/tree/remake/mininet/polka-example]. This is achieved by using a composition of checksum functions on stateless core switches. It can then be checked by a trusted party that knows the `node_id`s independently. // This should be abstract?

// = Related Works
// // does this section make sense?

// This is an extension of PolKA, a protocol that uses stateless _Residue Number System_-based Source Routing scheme@polka.

// This work is just part of a complete system, PathSec@pathsec. PathSec also deals with accessibility, auditability, and other aspects of a fully-featured Proof of Transit (PoT) network. This works only relates to the verifiability aspect of PathSec.

= Problem Definition

// Let $G = (V, E)$ be a graph representing the network topology, where $V$ is the set of nodes (switches) and $E$ is the set of edges (links).
Let $i$ be the source node (#text(weight: "bold")[i]ngress node) and $e$ be the destination node (#text(weight: "bold")[e]gress node). Let path $limits(P)_(i->e)$ be a sequence of nodes:

$ limits(P)_(i->e) = (i, s_1, s_2, ..., s_(n - 1), s_n, e) $ <eq:path-def>
where
/ $P$: Path from $i$ to $e$.
/ $s_n$: $n$-th core switch in the path.
/ $i$: Ingress edge (source).
/ $e$: Egress edge (destination).

In PolKA, the route up to the protocol boundary (usually, the SDN border) is defined in $i$@potpolka. $i$ sets the packet header with enough information for each core node to calculate the next hop. Calculating each hop is done using Chinese Remainder Theorem (CRT) and the Residue Number System (RNS)@polkap4, and is out of the scope of this paper. All paths are assumed to be both valid and all information correct unless stated otherwise.

The main problem we are trying to solve is path validation, that is, to have a way to ensure if the packets are actually following the path defined. Notably, it does not require verification, that is, listing the switches traversed is not required. // True/False problem

A solution should be able to identify if:
+ The packet has passed through the switches in the Path.
+ The packet has passed through the correct order of switches.
+ The packet has not passed through any switch that is not in the Path.

More formally, given a sequence of switches $limits(P)_(i->e)$, and a captured sequence of switches actually traversed $P_j$, a solution should identify if $limits(P)_(i->e) = P_j$.


= Solution Proposal

Each node's execution plan is stateless and can alter the header of the packet, which we will use to detect if the path taken is correct. So, a node $s_i$ can be viewed as a function $g_s_i (x)$.

In order to represent all nodes by the same function (for implementation purposes/* ?? */), we assign a distinct value $k$ for each $s$ node, and use a bivariate function $f(k_s_i, x) = f_s_i (x)$.
By using functions in two variables, we force one of the variables to have any uniquely per-node value, ensuring that the function is unique for each switch, that is, $f_s_y (x) != f_s_z (x) <=> y != z$.

Using function composition is a good way to propagate errors since it preserves the order-sensitive property of the path, since $f compose g != g compose f$ in a general case.
Each node will execute a single function of this composition, using the previous node's output as input.
In this way:

$ (f_s_1 compose f_s_2 compose f_s_3)(x) = f(k_s_3, f(k_s_2, f(k_s_1, x))) $
/ $s_i$: $i$-th switch in the path.
/ $f_s_i (x)$: Function representing switch $s_i$.
/ $k_s_i$: Unique identifier for switch $s_i$.

== Assumptions

+ Each node is assumed to be secure, that is, no node will alter the packet in any way that is not expected. This is a common assumption in SDN networks, where a trusted party is the only entity that can alter the network state.
+ Every link is assumed to be perfect, that is, no packet loss, no packet corruption, and no packet duplication.
+ Protocol boundary is IPv4. This means that PolKA is only used inside this network, and only IPv4 is used outside.


== Setup

All implementation and experiments took place on a VM#footnote[Available on PolKA's repository https://github.com/nerds-ufes/polka] setup with Mininet-wifi@mininet-wifi, and were targeting Mininet's@mininet Behavioral Model version 2 (BMv2)@bmv2. Wireshark@wireshark was used to analyze packets, and Scapy@scapy was used to parse packets programatically and automatic tests.

== Implementation

By making the function $f$ a checksum function, and the unique identifier $k_s_i$ as the `node_id`, we apply an input data into a chain checksum functions and verify if they match. For additional validation, we also integrate the calculated exit port into the checksum, covering some other forms of attacks or errors.

It /*TODO ???*/ was implemented as a version on PolKA, this means it uses the same `ethertype` `0x1234` and is interoperable with PolKA. Up-to-date PolKA headers were used (and upgraded from the forked version) to ensure compatibility. It uses the `version` header field to differentiate between regular PolKA version packets and what we call _probe_ packets. PolKA packets uses version `0x01`, and probe packets uses version `0xF1`.

@topology:base shows the used topology used in the experiments.

#{
  let node_base = node.with(stroke: 0.5pt, inset: 4pt)
  let switch = node_base.with(shape: shapes.octagon, fill: aqua)
  let edge_router = node_base.with(shape: shapes.pill, fill: lime)
  let host = node_base.with(shape: shapes.rect, fill: yellow, inset: 3.5pt)
  [#figure(
      caption: [Topology setup.\ #diagram(switch[$s_n$]) are core switches, #diagram(edge_router[$e_n$]) are edge switches, #diagram(host[$h_n$]) are hosts.],
      diagram(
        // debug: 1,
        label-size: 6pt,
        label-sep: 2pt,
        spacing: 2em,
        {

          let first_1 = 1
          let last_1 = 10
          for i in range(first_1, last_1+1) {
            let s = "s" + str(i)
            switch((i, 0), name: label(s))[$s_#i$]
            if i > first_1 {
              if i == 2 {
                edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 1, label-pos: 0.2)
              } else {
                edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 2, label-pos: 0.2)
              }
              edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 1, label-pos: 0.8)
            }
            edge("<->", label-pos: 0.2, label-side: left, label: 0)
            let e = "e" + str(i)
            edge_router((rel: (0, 1)), name: label(e))[$e_#i$]
            if i > first_1 {
              let h = "h" + str(i)
              edge("<->")
              host((rel: (0, 1)), name: label(h))[$h_#i$]
            }
          }


          host((rel: (-0.3, 1), to: <e1>), name: <h1>)[$h_1$]
          edge("<->", <e1>)
          host((rel: (0.3, 1), to: <e1>), name: <h11>)[$h_11$]
          edge("<->", <e1>)

        },
      ),
    ) <topology:base>]
}

This reads as follows: $s_1$ connects on port $1$ to $s_2$'s port $1$, and on port $0$ to $e_1$. $s_2$ connects on port $1$ to $s_1$'s port $1$, and on port $2$ to $s_3$'s port $1$, and to $e_2$ on port $0$, and so on.

=== Parsing

Parsing is done in edge nodes as follows:
- If an IPv4 protocol `ethertype` field is detected (`0x0800`), it must be a packet from outside the network, it must be wrapped and routed by the same edge node that parsed it. Let call this process be called _encapsulation_;
- If a PolKA protocol `ethertype` field is detected (`0x1234`), it must be a packet from inside the network, since the protocol boundary is IPv4, the original IPv4 packet must be unwrapped. Let this process be called _decapsulation_.

On core nodes, the packet is only parsed as PolKA packets, but it can be either a regular PolKA packet or a probe packet. If a probe packet version is detected, the probe packet header is parsed aswell, otherwise the packet is treated a regular PolKA packet.

The implementation for parsing on edge nodes can be found in @app:edge_parser, and for core nodes in @app:core_parser.


=== Encapsulation <node_id_notrequired>

PolKA headers consists of the route polynomial (`routeid`), along with `version`, `ttl` and `proto` (stores the original `ethertype`). `route_id` calculation is out of the scope of this paper.

A new header is added for probe packets, containing a 32 bit `key` and 32 bit `l_hash`.

During encapsulation of a probe packet, a random number is generated, and is used as `key`, for reproducibility and a seed for our composition. Edge nodes does not execute checksum functions and only repeats the key into the checksum field `l_hash`, so `node_id` for encapsulation is not required.

After encapsulation, the packet is sent to the next hop.

The implementation for encapsulation and related headers can be found in @app:encapsulation.

=== Composition

Every core node does checksum trying to congregate the previous `l_hash`, the calculated next hop port and it's own `node_id` into the 32 bit field. Currently, it is implemented as such:

$ #raw("l_hash") <- "CRC32" ("exit port" xor #raw("l_hash") xor #raw("node_id")) $

The CRC32 checksum function used currently is the one available by BMv2 standard library, and through testing, it was found out to be ISO HDLC#footnote[https://reveng.sourceforge.io/crc-catalogue/all.htm#crc.cat.crc-32-iso-hdlc].

The algorithm was verified externally through another program simulating all the composition steps, with source available#footnote[https://github.com/Henriquelay/polka_probe_checker/], making use of the `crc` library crate#footnote[https://github.com/mrhooray/crc-rs], and checked with gathered data.

The implementation for a node doing an individual checksum calculation step can be found in @app:calculation.

=== Decapsulation

At the egress node, Polka headers are dropped and the packet becomes an identical packet to what the ingress node received. The probe packet header is also dropped. The packet is then sent to the host. No checksum is calculated, so `node_id` is not required. Thus, together with @node_id_notrequired, the `node_id` is not used for validation on edge nodes.

The implementation for decapsulation can be found in @app:decapsulation.

== Example

A simple example of a packet traversing a network with 10 core switches is shown in the figure below. Exit port is calculated by PolKA. In the examples, we are measuring $limits(P)_(e_1->e_10) = (e_1, #range(1,11).map(i => $s_#i$).join($,$), e_10)$


#let inttohexstr(a) = "0x" + str(a, base: 16)
#let calc_crc32(a, b, c) = $"CRC32"(#raw(inttohexstr(a)) xor #raw(inttohexstr(b)) xor #raw(inttohexstr(c)))$
#figure(
  caption: [Packet trace while traversing $limits(P)_(e_1->e_10)$.],
  table(
      columns: 5,
      table.header(
        [Node],
        [`node_id`],
        [`exit_port`],
        [Calculation],
        [`l_hash`],
      ),

      /*
      *** Comparing 0x61e8d6e7, expects 0x61e8d6e7 on node 0x00ff ok ✅
      *** Comparing 0xae91434c, expects 0xae91434c on node 0x002b ok ✅
      *** Comparing 0x08c97f5f, expects 0x08c97f5f on node 0x002d ok ✅
      *** Comparing 0xeff1aad2, expects 0xeff1aad2 on node 0x0039 ok ✅
      *** Comparing 0x08040c89, expects 0x08040c89 on node 0x003f ok ✅
      *** Comparing 0xaa99ae2e, expects 0xaa99ae2e on node 0x0047 ok ✅
      *** Comparing 0x7669685e, expects 0x7669685e on node 0x0053 ok ✅
      *** Comparing 0x03e1e388, expects 0x03e1e388 on node 0x008d ok ✅
      *** Comparing 0x2138ffd3, expects 0x2138ffd3 on node 0x00bd ok ✅
      *** Comparing 0x1ef2cbbe, expects 0x1ef2cbbe on node 0x00d7 ok ✅
      *** Comparing 0x99c5fe05, expects 0x99c5fe05 on node 0x00f5 ok ✅
      */

      $e_1$,  ""       , `1` , [Generation]                      , `0x61e8d6e7`,
      $s_1$,  `0x002b` , `1` , calc_crc32(0x61e8d6e7, 1, 0x002b) , `0xae91434c`,
      $s_2$,  `0x002d` , `2` , calc_crc32(0xae91434c, 2, 0x002d) , `0x08c97f5f`,
      $s_3$,  `0x0039` , `2` , calc_crc32(0x08c97f5f, 2, 0x0039) , `0xeff1aad2`,
      $s_4$,  `0x003f` , `2` , calc_crc32(0xeff1aad2, 2, 0x003f) , `0x08040c89`,
      $s_5$,  `0x0047` , `2` , calc_crc32(0x08040c89, 2, 0x0047) , `0xaa99ae2e`,
      $s_6$,  `0x0053` , `2` , calc_crc32(0xaa99ae2e, 2, 0x0053) , `0x7669685e`,
      $s_7$,  `0x008d` , `2` , calc_crc32(0x7669685e, 2, 0x008d) , `0x03e1e388`,
      $s_8$,  `0x00bd` , `2` , calc_crc32(0x03e1e388, 2, 0x00bd) , `0x2138ffd3`,
      $s_9$,  `0x00d7` , `2` , calc_crc32(0x2138ffd3, 2, 0x00d7) , `0x1ef2cbbe`,
      $s_10$, `0x00f5` , `0` , calc_crc32(0x1ef2cbbe, 0, 0x00f5) , `0x99c5fe05`,
      $e_10$, ""       , `0` , [Decapsulation]                                 , `0x99c5fe05`,
    ),
) <example:base>


== Adversity scenarios

The solution has been tested against some adversarial scenarios, and checked against the same initial seed but under the base topology as described on @topology:base.

#let green_cells(..cells) = cells.pos().map(it => table.cell(fill: lime.lighten(30%), it))
#let red_cells(..cells) = cells.pos().map(it => table.cell(fill: red.lighten(20%), it))

=== Addition <scenario:addition>

An attacker PolKA switch $s_555$ was added between $s_5$ and $s_6$, as shown in @topology:addition. The packet was sent from $e_1$ to $e_10$. Suppose the attacking switch is properly connected in the ports that PolKA uses for this route, the packet is properly routed with PolKA, but the checksums will not match when validating the path in the future. The packet trace is shown in @example:addition. Note the error propagating nature of composing checksums.

#figure(
  caption: [Topology setup for addition scenario.],
  diagram(
      // debug: 1,
      spacing: 2em,
      label-size: 6pt,
      label-sep: 2pt,
      {

      let node_base = node.with(stroke: 0.5pt, inset: 4pt)
      let switch = node_base.with(shape: shapes.octagon, fill: aqua)
      let edge_router = node_base.with(shape: shapes.pill, fill: lime)
      let host = node_base.with(shape: shapes.rect, fill: yellow, inset: 3.5pt)
        let first_1 = 1
        let last_1 = 10
        for i in range(first_1, last_1+1) {
          let s = "s" + str(i)
          switch((i, 0), name: label(s))[$s_#i$]
          if i > first_1 and i != 6 {
            if i == 2 {
              edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 1, label-pos: 0.2)
            } else {
              edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 2, label-pos: 0.2)
            }
            edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 1, label-pos: 0.8)
          }
          edge("<->", label-pos: 0.2, label-side: left, label: 0)
          let e = "e" + str(i)
          edge_router((rel: (0, 1)), name: label(e))[$e_#i$]
          if i > first_1 {
            let h = "h" + str(i)
            edge("<->")
            host((rel: (0, 1)), name: label(h))[$h_#i$]
          }
        }


        host((rel: (-0.3, 1), to: <e1>), name: <h1>)[$h_1$]
        edge("<->", <e1>)
        host((rel: (0.3, 1), to: <e1>), name: <h11>)[$h_11$]
        edge("<->", <e1>)

        switch((rel: (0, -1), to:(<s5>, 50%, <s6>)), name: <s555>)[$s_555$]
        edge("<->", <s5>, 2, label-pos: 0.8)
        edge("<->", <s5>, 0, label-pos: 0.3)
        edge("<->", <s6>, 1, label-pos: 0.8)
        edge("<->", <s6>, 1, label-pos: 0.3)
        },
      ),
) <topology:addition>

#figure(
  caption: [Packet trace while traversing $limits(P)_(e_1->e_10)$ with an unexpected addition $s_555$.],
  table(
      columns: 6,
      table.header(
        [Node],
        [`node_id`],
        [`exit_port`],
        [Calculation],
        [`l_hash`],
        [Expected],
      ),

      /*
      *** Comparing 0xabadcafe, expects 0xabadcafe on node 0x00ff:e1-eth2 ✅ ok
      *** Comparing 0xabadcafe, expects 0xabadcafe on node 0x00ff:s1-eth1 ✅ ok
      *** Comparing 0x432cf798, expects 0x432cf798 on node 0x002b:s1-eth2 ✅ ok
      *** Comparing 0x432cf798, expects 0x432cf798 on node 0x002b:s2-eth2 ✅ ok
      *** Comparing 0xe04df688, expects 0xe04df688 on node 0x002d:s2-eth3 ✅ ok
      *** Comparing 0xe04df688, expects 0xe04df688 on node 0x002d:s3-eth2 ✅ ok
      *** Comparing 0xe8f0142c, expects 0xe8f0142c on node 0x0039:s3-eth3 ✅ ok
      *** Comparing 0xe8f0142c, expects 0xe8f0142c on node 0x0039:s4-eth2 ✅ ok
      *** Comparing 0xb452022a, expects 0xb452022a on node 0x003f:s4-eth3 ✅ ok
      *** Comparing 0xb452022a, expects 0xb452022a on node 0x003f:s5-eth2 ✅ ok
      *** Comparing 0x4450d2d2, expects 0x4450d2d2 on node 0x0047:s5-eth3 ✅ ok
      *** Comparing 0x4450d2d2, expects 0x4450d2d2 on node 0x0047:s555-eth0 ✅ ok
      *** Comparing 0x5b0fce3e, expects 0xe9367b57 on node 0x0047:s555-eth1 ❌ Digest does not match
      *** Comparing 0x5b0fce3e, expects 0xe9367b57 on node 0x0047:s6-eth4 ❌ Digest does not match
      *** Comparing 0xc967a61d, expects 0x991182c1 on node 0x0053:s6-eth3 ❌ Digest does not match
      *** Comparing 0xc967a61d, expects 0x991182c1 on node 0x0053:s7-eth2 ❌ Digest does not match
      *** Comparing 0xf6c27aa4, expects 0x35e72e11 on node 0x008d:s7-eth3 ❌ Digest does not match
      *** Comparing 0xf6c27aa4, expects 0x35e72e11 on node 0x008d:s8-eth2 ❌ Digest does not match
      *** Comparing 0x38d0bc4f, expects 0xaa152eb9 on node 0x00bd:s8-eth3 ❌ Digest does not match
      *** Comparing 0x38d0bc4f, expects 0xaa152eb9 on node 0x00bd:s9-eth2 ❌ Digest does not match
      *** Comparing 0xb6ff911a, expects 0x1a1573e7 on node 0x00d7:s9-eth3 ❌ Digest does not match
      *** Comparing 0xb6ff911a, expects 0x1a1573e7 on node 0x00d7:s10-eth2 ❌ Digest does not match
      *** ❌ Route length does not match expected. Expected 22, got 24
      *** ❌ Leftover packets:
      *** 0x882d8e93 on node 0x00f5:s10-eth1
      *** 0x882d8e93 on node 0x00f5:e10-eth2
      */

      ..green_cells(
        $e_1$, ""         , `1` , [Generation]                      , `0xabadcafe`, `0xabadcafe`,
        $s_1$, `0x002b`   , `1` , calc_crc32(0xabadcafe, 1, 0x002b) , `0x432cf798`, `0x432cf798`,
        $s_2$, `0x002d`   , `2` , calc_crc32(0x432cf798, 2, 0x002d) , `0xe04df688`, `0xe04df688`,
        $s_3$, `0x0039`   , `2` , calc_crc32(0xe04df688, 2, 0x0039) , `0xe8f0142c`, `0xe8f0142c`,
        $s_4$, `0x003f`   , `2` , calc_crc32(0xe8f0142c, 2, 0x003f) , `0xb452022a`, `0xb452022a`,
        $s_5$, `0x0047`   , `2` , calc_crc32(0xb452022a, 2, 0x0047) , `0x4450d2d2`, `0x4450d2d2`
      ),
      ..red_cells(
        $s_555$, `0x0047` , `1` , calc_crc32(0x4450d2d2, 1, 0x0047) , `0x5b0fce3e`, ""          ,
        $s_6$, `0x0053`   , `2` , calc_crc32(0x5b0fce3e, 2, 0x0053) , `0xc967a61d`, `0xe9367b57`,
        $s_7$, `0x008d`   , `2` , calc_crc32(0xc967a61d, 2, 0x008d) , `0xf6c27aa4`, `0x991182c1`,
        $s_8$, `0x00bd`   , `2` , calc_crc32(0xf6c27aa4, 2, 0x00bd) , `0x38d0bc4f`, `0x35e72e11`,
        $s_9$, `0x00d7`   , `2` , calc_crc32(0x38d0bc4f, 2, 0x00d7) , `0xb6ff911a`, `0xaa152eb9`,
        $s_10$, `0x00f5`  , `0` , calc_crc32(0xb6ff911a, 0, 0x00f5) , `0x882d8e93`, `0x1a1573e7`,
        $e_10$, ""        , `0` , [Decapsulation]                   , `0x882d8e93`, `0x1a1573e7`
      ),
    ),
) <example:addition>

=== Detour <scenario:detour>

An attacker tries to make a detour in the network, as shown in @topology:detour. The packet was sent from $e_1$ to $e_10$, and passed through the detour, as shown in @example:detour. The checksum will fail to validate when checking in the futures, as the function composition $f_s_555 (x) != f_s_6 (x)$. Note that this is only true when $k_s_555 != k_s_6$. As stated, the key must be unique per node, and so must be kept secret.

#figure(
  caption: [Topology setup for detour scenario.],
  diagram(
      // debug: 1,
      spacing: 2em,
      label-size: 6pt,
      label-sep: 2pt,
      {

      let node_base = node.with(stroke: 0.5pt, inset: 4pt)
      let switch = node_base.with(shape: shapes.octagon, fill: aqua)
      let edge_router = node_base.with(shape: shapes.pill, fill: lime)
      let host = node_base.with(shape: shapes.rect, fill: yellow, inset: 3.5pt)
        let first_1 = 1
        let last_1 = 10
        for i in range(first_1, last_1+1) {
          let s = "s" + str(i)
          switch((i, 0), name: label(s))[$s_#i$]
          if i > first_1 and i not in (6,7) {
            if i == 2 {
              edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 1, label-pos: 0.2)
            } else {
              edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 2, label-pos: 0.2)
            }
            edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 1, label-pos: 0.8)
          }
          edge("<->", label-pos: 0.2, label-side: left, label: 0)
          let e = "e" + str(i)
          edge_router((rel: (0, 1)), name: label(e))[$e_#i$]
          if i > first_1 {
            let h = "h" + str(i)
            edge("<->")
            host((rel: (0, 1)), name: label(h))[$h_#i$]
          }
        }


        host((rel: (-0.3, 1), to: <e1>), name: <h1>)[$h_1$]
        edge("<->", <e1>)
        host((rel: (0.3, 1), to: <e1>), name: <h11>)[$h_11$]
        edge("<->", <e1>)

        switch((rel: (0, -1), to:(<s5>, 50%, <s7>)), name: <s555>)[$s_555$]
        edge("<-o", <s5>, label-pos: 0.2, 0)
        edge("<-o", <s5>, label-pos: 0.8, 2)
        edge("o->", <s7>, label-pos: 0.2, 1)
        edge("o->", <s7>, label-pos: 0.8, 3)
        edge(<s5>, "<-o", <s6>, label-pos: 0.8, 1)
        edge(<s6>, "<-o", <s7>, label-pos: 0.8, 1)
        },
      ),
) <topology:detour>

#figure(
  caption: [Packet trace while traversing $limits(P)_(e_1->e_10)$ with an unexpected detour.],
  table(
      columns: 6,
      table.header(
        [Node],
        [`node_id`],
        [`exit_port`],
        [Calculation],
        [`l_hash`],
        [Expected]
      ),

      /*
      *** Comparing 0xbaddc0de, expects 0xbaddc0de on node 0x00ff:e1-eth2 ✅ ok
      *** Comparing 0xbaddc0de, expects 0xbaddc0de on node 0x00ff:s1-eth1 ✅ ok
      *** Comparing 0x3ef96770, expects 0x3ef96770 on node 0x002b:s1-eth2 ✅ ok
      *** Comparing 0x3ef96770, expects 0x3ef96770 on node 0x002b:s2-eth2 ✅ ok
      *** Comparing 0x2dca9942, expects 0x2dca9942 on node 0x002d:s2-eth3 ✅ ok
      *** Comparing 0x2dca9942, expects 0x2dca9942 on node 0x002d:s3-eth2 ✅ ok
      *** Comparing 0x11797334, expects 0x11797334 on node 0x0039:s3-eth3 ✅ ok
      *** Comparing 0x11797334, expects 0x11797334 on node 0x0039:s4-eth2 ✅ ok
      *** Comparing 0x98081e3e, expects 0x98081e3e on node 0x003f:s4-eth3 ✅ ok
      *** Comparing 0x98081e3e, expects 0x98081e3e on node 0x003f:s5-eth2 ✅ ok
      *** Comparing 0x3332e012, expects 0x3332e012 on node 0x0047:s5-eth3 ✅ ok
      *** Comparing 0x3332e012, expects 0x3332e012 on node 0x0047:s555-eth0 ✅ ok
      *** Comparing 0x90a0df94, expects 0x22996afd on node 0x0047:s555-eth1 ❌ Digest does not match
      *** Comparing 0x90a0df94, expects 0x22996afd on node 0x0047:s7-eth2 ❌ Digest does not match
      *** Comparing 0xbebe4372, expects 0x8fa3987d on node 0x008d:s7-eth3 ❌ Digest does not match
      *** Comparing 0xbebe4372, expects 0x8fa3987d on node 0x008d:s8-eth2 ❌ Digest does not match
      *** Comparing 0x5aafa7f2, expects 0xf4b50950 on node 0x00bd:s8-eth3 ❌ Digest does not match
      *** Comparing 0x5aafa7f2, expects 0xf4b50950 on node 0x00bd:s9-eth2 ❌ Digest does not match
      *** Comparing 0x649b8554, expects 0xd0c29e67 on node 0x00d7:s9-eth3 ❌ Digest does not match
      *** Comparing 0x649b8554, expects 0xd0c29e67 on node 0x00d7:s10-eth2 ❌ Digest does not match
      *** Comparing 0xf46427bf, expects 0x13ff41c1 on node 0x00f5:s10-eth1 ❌ Digest does not match
      *** Comparing 0xf46427bf, expects 0x13ff41c1 on node 0x00f5:e10-eth2 ❌ Digest does not match
      */

      ..green_cells(
        $e_1$, ""         , `1` , [Generation]                      , `0xbaddc0de`, `0xbaddc0de`,
        $s_1$, `0x002b`   , `1` , calc_crc32(0xbaddc0de, 1, 0x002b) , `0x3ef96770`, `0x3ef96770`,
        $s_2$, `0x002d`   , `2` , calc_crc32(0x3ef96770, 2, 0x002d) , `0x2dca9942`, `0x2dca9942`,
        $s_3$, `0x0039`   , `2` , calc_crc32(0x2dca9942, 2, 0x0039) , `0x11797334`, `0x11797334`,
        $s_4$, `0x003f`   , `2` , calc_crc32(0x11797334, 2, 0x003f) , `0x98081e3e`, `0x98081e3e`,
        $s_5$, `0x0047`   , `2` , calc_crc32(0x98081e3e, 2, 0x0047) , `0x3332e012`, `0x3332e012`
      ),
      ..red_cells(
        $s_555$, `0x0047` , `1` , calc_crc32(0x3332e012, 1, 0x0047) , `0x90a0df94`, `0x22996afd`,
        $s_7$, `0x0053`   , `2` , calc_crc32(0x90a0df94, 2, 0x0053) , `0xbebe4372`, `0x8fa3987d`,
        $s_8$, `0x008d`   , `2` , calc_crc32(0xbebe4372, 2, 0x008d) , `0x5aafa7f2`, `0xf4b50950`,
        $s_9$, `0x00bd`   , `2` , calc_crc32(0x5aafa7f2, 2, 0x00bd) , `0x649b8554`, `0xd0c29e67`,
        $s_10$, `0x00d7`  , `0` , calc_crc32(0x649b8554, 2, 0x00d7) , `0xf46427bf`, `0x13ff41c1`,
        $e_10$, ""        , `0` , [Decapsulation]                   , `0xf46427bf`, `0x13ff41c1`
      ),
    ),
) <example:detour>

=== Skipping <scenario:skipping>

Miconfigured links can cause packets to skip nodes, as shown in @topology:skipping. The packet was sent from $e_1$ to $e_10$, and passed through the skipping, as shown in @example:skipping. The checksum will not match when validating the path in the future, as the packet did not pass through the expected nodes.

#figure(
  caption: [Topology setup for skipping scenario.],
  diagram(
      // debug: 1,
      spacing: 2em,
      label-size: 6pt,
      label-sep: 2pt,
      {

      let node_base = node.with(stroke: 0.5pt, inset: 4pt)
      let switch = node_base.with(shape: shapes.octagon, fill: aqua)
      let edge_router = node_base.with(shape: shapes.pill, fill: lime)
      let host = node_base.with(shape: shapes.rect, fill: yellow, inset: 3.5pt)
        let first_1 = 1
        let last_1 = 10
        for i in range(first_1, last_1+1) {
          let s = "s" + str(i)
          switch((i, 0), name: label(s))[$s_#i$]
          if i > first_1 and i not in (5,6,) {
            if i == 2 {
              edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 1, label-pos: 0.2)
            } else {
              edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 2, label-pos: 0.2)
            }
            edge(label("s" + str(i - 1)), label("s" + str(i)), "<->", 1, label-pos: 0.8)
          }
          edge("<->", label-pos: 0.2, label-side: left, label: 0)
          let e = "e" + str(i)
          edge_router((rel: (0, 1)), name: label(e))[$e_#i$]
          if i > first_1 {
            let h = "h" + str(i)
            edge("<->")
            host((rel: (0, 1)), name: label(h))[$h_#i$]
          }
        }


        host((rel: (-0.3, 1), to: <e1>), name: <h1>)[$h_1$]
        edge("<->", <e1>)
        host((rel: (0.3, 1), to: <e1>), name: <h11>)[$h_11$]
        edge("<->", <e1>)


        edge(<s4>, <s6>, "<->", 2, bend: 30deg, label-pos: 0.2)
        edge(<s4>, <s6>, "<->", 1, bend: 30deg, label-pos: 0.8)
        },
      ),
) <topology:skipping>

#figure(
  caption: [Packet trace while traversing $limits(P)_(e_1->e_10)$ with an unexpected skip.],
  table(
      columns: 6,
      table.header(
        [Node],
        [`node_id`],
        [`exit_port`],
        [Calculation],
        [`l_hash`],
        [Expected]
      ),

      /*
      *** 🔍 Tracing new route
      *** Comparing 0x61e8d6e7, expects 0x61e8d6e7 on node 0x00ff:e1-eth2 ✅ ok
      *** Comparing 0x61e8d6e7, expects 0x61e8d6e7 on node 0x00ff:s1-eth1 ✅ ok
      *** Comparing 0xae91434c, expects 0xae91434c on node 0x002b:s1-eth2 ✅ ok
      *** Comparing 0xae91434c, expects 0xae91434c on node 0x002b:s2-eth2 ✅ ok
      *** Comparing 0x08c97f5f, expects 0x08c97f5f on node 0x002d:s2-eth3 ✅ ok
      *** Comparing 0x08c97f5f, expects 0x08c97f5f on node 0x002d:s3-eth2 ✅ ok
      *** Comparing 0xeff1aad2, expects 0xeff1aad2 on node 0x0039:s3-eth3 ✅ ok
      *** Comparing 0xeff1aad2, expects 0xeff1aad2 on node 0x0039:s4-eth2 ✅ ok
      *** Comparing 0x08040c89, expects 0x08040c89 on node 0x003f:s4-eth3 ✅ ok
      *** Comparing 0x08040c89, expects 0x08040c89 on node 0x003f:s6-eth2 ✅ ok
      *** Comparing 0xb0437a53, expects 0xaa99ae2e on node 0x0053:s6-eth3 ❌ Digest does not match
      *** Comparing 0xb0437a53, expects 0xaa99ae2e on node 0x0053:s7-eth2 ❌ Digest does not match
      *** Comparing 0x63589d0a, expects 0x7669685e on node 0x008d:s7-eth3 ❌ Digest does not match
      *** Comparing 0x63589d0a, expects 0x7669685e on node 0x008d:s8-eth2 ❌ Digest does not match
      *** Comparing 0x629b7b3b, expects 0x03e1e388 on node 0x00bd:s8-eth3 ❌ Digest does not match
      *** Comparing 0x629b7b3b, expects 0x03e1e388 on node 0x00bd:s9-eth2 ❌ Digest does not match
      *** Comparing 0xbd53e851, expects 0x2138ffd3 on node 0x00d7:s9-eth3 ❌ Digest does not match
      *** Comparing 0xbd53e851, expects 0x2138ffd3 on node 0x00d7:s10-eth2 ❌ Digest does not match
      *** Comparing 0x90bdf731, expects 0x1ef2cbbe on node 0x00f5:s10-eth1 ❌ Digest does not match
      *** Comparing 0x90bdf731, expects 0x1ef2cbbe on node 0x00f5:e10-eth2 ❌ Digest does not match
      */

      ..green_cells(
        $e_1$, ""         , `1` , [Generation]                      , `0x61e8d6e7`, `0x61e8d6e7`,
        $s_1$, `0x002b`   , `1` , calc_crc32(0x61e8d6e7, 1, 0x002b) , `0xae91434c`, `0xae91434c`,
        $s_2$, `0x002d`   , `2` , calc_crc32(0xae91434c, 2, 0x002d) , `0x08c97f5f`, `0x08c97f5f`,
        $s_3$, `0x0039`   , `2` , calc_crc32(0x08c97f5f, 2, 0x0039) , `0xeff1aad2`, `0xeff1aad2`,
        $s_4$, `0x003f`   , `2` , calc_crc32(0xeff1aad2, 2, 0x003f) , `0x08040c89`, `0x08040c89`
      ),
      ..red_cells(
        $s_6$, `0x0053`   , `2` , calc_crc32(0x08040c89, 2, 0x0053) , `0xb0437a53`, `0xaa99ae2e`,
        $s_7$, `0x008d`   , `2` , calc_crc32(0xb0437a53, 2, 0x008d) , `0x63589d0a`, `0x7669685e`,
        $s_8$, `0x00bd`   , `2` , calc_crc32(0x63589d0a, 2, 0x00bd) , `0x629b7b3b`, `0x03e1e388`,
        $s_9$, `0x00d7`   , `2` , calc_crc32(0x629b7b3b, 2, 0x00d7) , `0xbd53e851`, `0x2138ffd3`,
        $s_10$, `0x00f5`  , `0` , calc_crc32(0xbd53e851, 0, 0x00f5) , `0x90bdf731`, `0x1ef2cbbe`,
        $e_10$, ""        , `0` , [Decapsulation]                   , `0x90bdf731`, `0x1ef2cbbe`
      ),
    ),
) <example:skipping>

== Limitations

Upon developing the solution, a set of limitations were identified:
+ As with most cryptographic solutions, the system is only as secure as the key used. If the key is compromised, the entire system is compromised, since a malicious actor can easily generate the same checksums.
+ Replay attack is undetectable if metadata is disconsidered. This is due to the entry port not being included in the validation, which allows an attacker to replay the packet from a different port.

= Future Work

The plan, as per the repository name implies, is to implement a non-reversible hash function, SipHash, more specifically, HalfSipHash@siphash, to be used instead of the CRC32. This would make the system more secure, since CRC32 is a well-known as a checksum function that can be easily reversed@reversingCRC. Also, a proper data compression method for adding exit port and `node_id` into the checksum field is needed, since the current method is not optimal due to data loss.

In the future, it should be integrated into PathSec@pathsec, and to do so the ingress edge needs to report the generated `key`, and the egress edge will report the final checksum directly to a blockchain, for auditability and accessibility. Having it directly report to a blockchain instead of a third party circumvents trust issues.

An interesting work can be done to use some sort of rotating key architecture to detect replay attacks. This is a hard problem, since the key must be rotated in a way that the attacker cannot predict, and the key must be shared between the nodes in a secure, atomic way to prevent the network to enter an irrecoverable state.

Including the entry port in the checksum would also be an appreciable increase in security, since it increses the number of targets an attacker would need to breach at the same time to be able to alter the path.

A timing analysis and stress tests can both be done to check if the incurred overhead is acceptable for the network. This is important, since the network must be able to handle the increased load without dropping packets. A more robust solution would be to use a more secure hash function, such as SHA-256, but this would increase the overhead of the network, and would require a more powerful hardware to be able to handle the increased load.

= Conclusion

As the examples show, our solution is able to detect when a packet is not following the expected path for most cases, and can be used to detect misconfigurations in the network. The solution is not perfect, but it is a step in the right direction for a more secure network.

#bibliography("bib.yml")

#set heading(numbering: none)

= Appendix

#show: appendix

= Parsers <app:parsers>
== Edge Node <app:edge_parser>
```p4
parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        // Reads and pops the header. We will need to `.emit()` it back later
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            // If the packet comes from outside (ethernet packet)
            TYPE_IPV4: parse_ipv4;
            
            // If the packet comes inside (polka packet)
            TYPE_POLKA: parse_polka;
            
            // Any other packet
            default: accept;
        }
    }

    state parse_polka {
        packet.extract(hdr.polka);

        transition select(hdr.polka.version) {
            PROBE_VERSION: parse_polka_probe;
            // Any other packet
            default: parse_ipv4;
        }
    }

    state parse_polka_probe {
        packet.extract(hdr.polka_probe);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}
```

== Core Node <app:core_parser>
```p4
parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        meta.apply_sr = 0;
        transition verify_ethernet;
    }

    state verify_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            TYPE_POLKA: get_polka_header;
            // Should be dropped when apply_sr is 0
            // But can't use drop here on BMV2
            default: accept;
        }
    }

    state get_polka_header {
        meta.apply_sr = 1;
        packet.extract(hdr.polka);
        meta.route_id = hdr.polka.routeid;

        transition select(hdr.polka.version) {
            PROBE_VERSION: parse_polka_probe;
            // Any other packet
            default: accept;
        }
    }

    state parse_polka_probe {
        packet.extract(hdr.polka_probe);
        transition accept;
    }
}
```

= Encapsulation <app:encapsulation>
```p4
control TunnelEncap(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    action tdrop() {
        mark_to_drop(standard_metadata);
    }

    action add_sourcerouting_header (
        bit<9> port,
        bit<1> sr,
        mac_addr_t dmac,
        polka_route_t routeIdPacket
    ){
        // Has to be set to valid for changes to be commited
        hdr.polka.setValid();

        hdr.polka.version = REGULAR_VERSION;
        hdr.polka.ttl = 0xFF;
        
        meta.apply_sr = sr;
        standard_metadata.egress_spec = port;
        hdr.polka.routeid = routeIdPacket;
        hdr.ethernet.dst_mac_addr = dmac;

        hdr.polka.proto = TYPE_POLKA;
        // Replicating on both headers for consistency
        hdr.ethernet.ethertype = TYPE_POLKA;
    }

    // Adds a Polka header to the packet 
    // Table name can't be changed because it is the name defined by node configuration files
    table tunnel_encap_process_sr {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            // Actions names also can't be changed because they are the names defined by node configuration files
            add_sourcerouting_header;
            tdrop;
        }
        size = 1024;
        default_action = tdrop();
    }

    apply {
        tunnel_encap_process_sr.apply();

        if (meta.apply_sr == 0) {
            hdr.polka.setInvalid();
        // } else {
        // Not needed - it is already set to valid in inside match arm
        //     hdr.polka.setValid();
        }
    }
}
```

= Checksum Calculation <app:calculation>
```p4
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_POLKA = 0x1234;

const bit<8> REGULAR_VERSION = 0x01;
const bit<8> PROBE_VERSION = 0xF1;

#include hdr_ethernet.p4"
#include "hdr_ipv4.p4"
#include "hdr_polka.p4"

struct metadata {
    bit<1>   apply_sr;
    bit<9>   port;
    bit<16>  switch_id;
    polka_route_t route_id;
}

header polka_probe_t {
    bit<32> timestamp;
    bit<32> l_hash;
}

struct headers {
    ethernet_t    ethernet;
    polka_t       polka;
    polka_probe_t polka_probe;
    ipv4_t        ipv4;
```
```p4
control MySwitchId(
    inout headers hdr,
    inout metadata meta
) {
    action switchid (
        bit<16> switch_id
    ){
       meta.switch_id = switch_id;
    }

    // Adds a Polka header to the packet 
    // Table name can't be changed because it is the name defined by node configuration files
    table config {
        key = {
            meta.apply_sr: exact;
        }
        actions = {
            // Actions names also can't be changed because they are the names defined by node configuration files
            switchid;
        }
        size = 128;
    }

    apply {
        meta.apply_sr = 0;
        config.apply();
        hdr.polka.ttl = meta.switch_id[7:0];
    }
}

control MySignPacket(
    inout headers hdr,
    inout metadata meta
) {
    // Signs the packet
    apply {
        // Gets the routeId and installs it on meta.route_id
        MySwitchId.apply(hdr, meta);
        hdr.polka_probe.setValid();

        // At this point, `meta.port` should be written on already
        hdr.polka_probe.l_hash = (bit<32>) meta.port ^ hdr.polka_probe.l_hash ^ (bit<32>) meta.switch_id;

        bit<16> nbase = 0;
        bit<32> min_bound = 0;
        bit<32> max_bound = 0xFFFFFFFF;
        hash(
            hdr.polka_probe.l_hash,
            HashAlgorithm.crc32,
            min_bound,
            {hdr.polka_probe.l_hash},
            max_bound
        );
    }
}
```

= Decapsulation <app:decapsulation>
```p4
control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    // Removes extra headers from Polka packet, leaves it as if nothing had touched it.
    action tunnel_decap() {
        // Set ethertype to IPv4 since it is leaving Polka
        hdr.polka.proto = TYPE_IPV4;
        // Replicating on second header for consistency
        hdr.ethernet.ethertype = TYPE_IPV4;

        // Does not serialize routeid
        hdr.polka.setInvalid();

        // Should be enough to "decap" packet

        // In this example, port `1` is always the exit node
        standard_metadata.egress_spec = 1;
    }

    apply {
        if (hdr.ethernet.ethertype == TYPE_POLKA) {
            // Packet came from inside network, we need to make it a normal pkt
            tunnel_decap();
        } else {
            // Packet came from ouside network, we need to make it a polka pkt
            TunnelEncap.apply(hdr, meta, standard_metadata);
        }
        MyProbe.apply(hdr, meta);
    }
} 
```
