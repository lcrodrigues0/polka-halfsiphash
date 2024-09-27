#import "@preview/fletcher:0.5.1" as fletcher: diagram, node, edge, shapes

#set page(paper: "a4")
#set text(font: "New Computer Modern", size: 11pt)
#set par(justify: true)
#set heading(numbering: "1.")
#show link: it => text(blue, underline(it))

#let midsection(it) = align(center, text(size: 1.1em, weight: "bold", it))

#let title = [An Implementation of Verifiable Routing on PolKA]

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

#lorem(100)

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

#columns(1)[
  = Introduction

  Ever since Source Routing (SR) was proposed, there has been a need to ensure that packets traverse the network along the paths selected by the source, not only for security reasons but also to ensure that the network is functioning correctly and correctly configured. This is particularly important in the context of Software-Defined Networking (SDN), where the control plane can select paths based on a variety of criteria.

  In this paper, we propose a new P4@p4 implementation for a new protocol layer for PolKA@polka, able to do verify the actual route used for a packet. It is available on GitHub#footnote[https://github.com/Henriquelay/polka-halfsiphash/tree/remake/mininet/polka-example]. This is achieved by using a composition of hash functions on stateless core switches, each using a key to generate a digest that can be checked by the controller which knows the secrets. The controller can then verify that the packet traversed the network along the path selected by the source, ensuring that the network is functioning correctly.

  // = Related Works
  // // does this section make sense?

  // This is an extension of PolKA, a protocol that uses stateless _Residue Number System_-based Source Routing scheme@polka.

  // This work is just part of a complete system, PathSec@pathsec. PathSec also deals with accessibility, auditability, and other aspects of a fully-featured Proof of Transit (PoT) network. This works only relates to the verifiability aspect of PathSec.

  = Problem Definition

  // Let $G = (V, E)$ be a graph representing the network topology, where $V$ is the set of nodes (switches) and $E$ is the set of edges (links).
  Let $i$ be the source node (#text(weight: "bold")[i]ngress node) and $e$ be the destination node (#text(weight: "bold")[e]gress node). Let path $P$ be a sequence of nodes:

  $ limits(P)_(i->e) = (i, s_1, s_2, ..., s_(n - 1), s_n, e) $ <eq:path-def>
  where
  / $P$: Path from $i$ to $e$.
  / $s_n$: Core switch $n$ in the path.
  / $n$: Number of core switches in the path.
  / $i$: Ingress edge (source).
  / $e$: Egress edge (destination).

  In PolKA, the route up to the protocol boundary (usually, the SDN border) is defined in $i$@potpolka. $i$ sets the packet header with enough information for each core node to calculate the next hop. Calculating each hop is done using Chinese Remainder Theorem (CRT) and the Residue Number System (RNS)@polkap4, and is out of the scope of this paper. All paths are assumed to be both valid and all information correct unless stated otherwise.

  The main problem we are trying to solve is path validation, that is, to have a way to ensure if the packets are actually following the path defined. Notably, it does not require verification, that is, listing the switches traversed is not required. // True/False problem

  A solution should be able to identify if:
  1. The packet has passed through the switches in the path.
  2. The packet has passed through the correct order of switches.
  3. The packet has not passed through any switch that is not in the Path.

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

  PolKA and the proposed extension are open source, so it is assumed that any attacker can replicate a node perfectly. Protocol boundary is IPv4. This means that PolKA is only used inside this network. // Continue

  == Setup

  All implementation and experiments took place on a VM#footnote[Available on PolKA's repository https://github.com/nerds-ufes/polka] setup with Mininet-wifi@mininet-wifi, and were targeting Mininet's@mininet Behavioral Model version 2 (BMv2)@bmv2. Wireshark@wireshark was used to analyze packets, and Scapy@scapy was used to parse packets programatically.

  == Implementation

  By making the function $f$ is a checksum function, and the unique identifier $k_s_i$ as the `node_id`, we apply an input data into a chain checksum functions and verify if they match. The controller will act as a validator, since it already has access to all `node_id`. For additional verification, we also integrate the calculated exit port into the checksum, covering some other forms of

  It was implemented as a version on PolKA, this means it uses the same protocol identifier `0x1234` and is interoperable with PolKA. Up-to-date PolKA headers were used (and upgraded from the forked version) to ensure compatibility. It uses the `version` header field to differentiate between regular PolKA version packets and what we call _probe_ packets. PolKA packets uses version `0x01`, and probe packets uses version `0xF1`.

  @topology shows the used topology used in the experiments.

  #figure(
    caption: [Topology setup.\ $s_n$ are core switches, $e_n$ are edge switches, $h_n$ are hosts.],
    diagram(
      node-stroke: 0.5pt,
      node-inset: 4pt,
      // debug: 1,
      spacing: 2em,
      {
        let switch = node.with(shape: shapes.octagon, fill: aqua)
        let edge_router = node.with(shape: shapes.pill, fill: lime)
        let host = node.with(shape: shapes.rect, fill: yellow, inset: 3.5pt)

        let first_1 = 1
        let last_1 = 10
        for i in range(first_1, last_1+1) {
          let s = "s" + str(i)
          switch((i, 0), name: label(s))[$s_#i$]
          if i > first_1 {
            edge(label("s" + str(i - 1)), label("s" + str(i)), "<->")
          }
          edge("<->")
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
  ) <topology>

  === Parsing

  Parsing is done in edge nodes as follows:
  - If an IPv4 protocol EtherType is detected (`0x0800`), it must be a packet from outside the network, it must be wrapped and routed by the same edge node that parsed it. Let call this process be called _encapsulation_;
  - If a PolKA protocol EtherType is detected (`0x1234`), it must be a packet from inside the network, since the protocol boundary is IPv4, the original IPv4 packet must be unwrapped. Let this process be caleld _decapsulation_.

  === Encapsulation

  Polka headers consists of the route polynomial (`routeid`), along with `version`, `ttl` and `proto` (stores the original EtherType). `route_id` calculation is out of the scope of this paper.

  An additional header, added by this work, is added for probe packets, containing a 32 bit `key` and 32 bit `l_hash`.

  During encapsulation of a probe packet, a random number is generated, and is used as `key`, for reproducibility. Edge nodes does not execute checksum functions and only repeats the key into the checksum field.

  === Composition

  Every core node does checksum trying to congregate the previous `l_hash`, the calculated next hop port and it's own `node_id` into the 32 bit field. Currently, it is implemented as such:
  $
    #raw("l_hash") <- "CRC"_32 ("exit port" xor #raw("l_hash") xor #raw("node_id"))
  $

  The $"CRC"_32$ checksum function used is the one available by BMv2 standard library, and through testing, it was found out to be ISO HDLC, by comparing results.

  The algorithm was verified externally through another program written in Rust, with source also available#footnote[https://github.com/Henriquelay/polka_probe_checker/], making use of the `crc` library.

  === Decapsulation

  At the egress node, PolKA headers are dropped and the packet becomes an identical packet to what the ingress node received.

  This detects {{X Y Z}}


  = Limitations

  - Replay attack is undetectable if timing is not considered.

  = Future Work

  - Rotating key for switches for detecting replay attacks (holy shit this is hard)
  - Include entrance port in checksum

  #bibliography("bib.yml")

]
