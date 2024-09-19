#import "@preview/fletcher:0.5.1" as fletcher: diagram, node, edge, shapes

#set page(paper: "a4")
#set text(font: "New Computer Modern", size: 11pt)
#set par(justify: true)
#set heading(numbering: "I.1.a")
#show link: it => text(blue, underline(it))

#let midsection(it) = align(center, text(size: 1.1em, weight: "bold", it))

#let title = [An Implementation of Verifiable Routing on PolKA]

#midsection(text(size: 1.5em, title))

#{
  let UFESsym = sym.dagger
  let IFESsym = sym.dagger.double
  let UFES(it) = box()[#it#UFESsym]
  let IFES(it) = box()[#it#IFESsym]

  let authors_UFES = ("Henrique Coutinho Layber", "Roberta Lima Gomes", "Magnos Martinello", "Vitor B. Bonella")
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
  let keywords = ("Verifiable Routing", "Path Verification", "Proof-of-transit", "In-networking Programming")
  text(weight: "bold", keywords.join(keyword_sep))
}

#columns(1)[
  = Introduction

  Ever since Source Routing (SR) was proposed, there has been a need to ensure that packets traverse the network along the paths selected by the source, not only for security reasons but also to ensure that the network is functioning correctly and correctly configured. This is particularly important in the context of Software-Defined Networking (SDN), where the control plane can select paths based on a variety of criteria.

  In this paper, we propose a new P4@p4 implementation for a new protocol layer for PolKA@polka, able to do verify the actual route used for a packet. It is available on GitHub#footnote[https://github.com/Henriquelay/polka-halfsiphash/tree/remake/mininet/polka-example]. This is achieved by using a composition of hash functions on stateless core switches, each using a key to generate a digest that can be checked by the controller which knows the secrets. The controller can then verify that the packet traversed the network along the path selected by the source, ensuring that the network is functioning correctly.

  = Related Works
  // does this section make sense?

  This is an extension of PolKA, a protocol that uses stateless _Residue Number System_-based Source Routing scheme@polka.

  This work is just part of a complete system, PathSec@pathsec. PathSec also deals with accessibility, auditability, and other aspects of a fully-featured Proof of Transit (PoT) network. This works only relates to the verifiability aspect of PathSec.

  = Problem Definition

  Using simpler terms, in PolKA, the route up to a protocol boundary (usually, the SDN border) is defined in $s$@potpolka. $s$ calculates and sets the packet header with enough information for each node to calculate the next hop. Calculating each hop is done using Chinese Remainder Theorem (CRT) and the Residue Number System (RNS)@polkap4, and is out of the scope of this paper. All paths are assumed to be both valid and correct.

  Let $G = (V, E)$ be a graph representing the network topology, where $V$ is the set of nodes (switches) and $E$ is the set of edges (connections). Let $e$ be the source node (SDN ingress edge) and $d$ be the destination node (SDN egress edge). Let path $P$ be a sequence of nodes:

  $ P = (e, s_1, s_2, .., s_n, d) $ <math:path-def>
  where
  / $P$: Path from $e$ to $d$.
  / $s_i$: Core switch $i$ in the path.
  / $n$: Number of core switches in the path.
  / $e$: Ingress edge (source).
  / $d$: Egress edge (destination).

  The main problem we are trying to solve is to have a way to ensure if the packets are following the path defined by the source. Notably, the solution need not to list the switches traversed, but only to verify if the packet has passed through the correct path.

  A solution should be able to identify if:
  1. The packet has passed through the correct switches.
  2. The packet has passed through the correct order of switches.
  3. The packet has not passed through any switch that is not in the path.

  More formally, given a sequence of switches $P_e$ generated on the ingress $e$, and a sequence of switches actually traversed $P_j$, a solution should identify if $P_e = P_j$.


  @sr-diagram shows the most used topology used in the experiments.

  #figure(
    caption: [Topology setup],
    diagram(
      node-stroke: 0.5pt,
      node-inset: 4pt,
      // debug: 1,
      spacing: 1.5em,
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


        host((0.6, 2), name: <h1>)[$h_1$]
        edge("<->", <e1>)
        host((1.4, 2), name: <h11>)[$h_11$]
        edge("<->", <e1>)

        // Uncomment if h_n-2.. is needed

        // let first = -2
        // let offset = 1
        // let lim = range(first, 1)
        // for i in lim {
        //   let istr = if i == 0 {
        //       ""
        //     } else {
        //       str(i)
        //     }

        //   host(
        //     (rel: (offset + i + lim.len(), 0), to: label("h" + str(last_1))),
        //     name: label("hn" + str(-i)),
        //   )[$h_(n#istr)$]

        //   edge("<->")

        //   edge_router(
        //     (rel: (offset + i + lim.len(), 0), to: label("e" + str(last_1))),
        //     name: label("en" + str(-i)),
        //   )[$e_(n#istr)$]

        //   edge("<->")

        //   switch(
        //     (rel: (offset + i + lim.len(), 0), to: label("s" + str(last_1))),
        //     name: label("sn" + str(-i)),
        //   )[$s_(n#istr)$]
        //   if i > first {
        //     edge(label("sn" + str(-i + 1)), label("sn" + str(-i)), "<->")
        //   }
        // }

        // node((rel:(0, 0), to: (label("s" + str(last_1)), 50%, label("sn"+str(-first)))), stroke: none)[...]
        // edge(label("sn"+str(-first)), "<->")
        // edge(label("s" + str(last_1)), "<->")
        // node((rel:(0, 0), to: (label("h" + str(last_1)), 50%, label("hn"+str(-first)))), stroke: none)[...]
        // node((rel:(0, 0), to: (label("e" + str(last_1)), 50%, label("en"+str(-first)))), stroke: none)[...]

        // node((rel: (0pt, 24pt), to: (<s1>, 50%, <sn0>)), "controller", name: <controller>, shape: shapes.rect, fill: silver)
      },
    ),
  ) <sr-diagram>

  = Solution Proposal

  Since the system is stateless, using function composition is a good way to propagate errors. Function composition preserves the order-sensitive property of the path, since $f compose g != g compose f$ in a general case.
  Each node will execute a single function of this composition, using the previous node's output as input. 
  By using injective functions in two variables, we can use one of the variables to have any uniquely per-node value, ensuring that the function is unique for each switch, ensuring $f_s_1(x) != f_s_2(x)$ for nodes $s_1$ and $s_2$.
  In this way:

  $ f_s_1 compose f_s_2 compose f_s_3 = f(id_s_3, f(id_s_2, f(id_s_1, x))) $
  / $f_s_i$: Function for switch $s_i$.
  / $id_s_i$: Unique identifier for switch $s_i$.

  The function $f$ is a hash function, and the unique identifier $id_s_i$ is the switch's ID.
  TODO exit port is also added

  == Assumption

  Controller that knows all IDs, and the hash function used.

  == Implementation

  It was implemented {{THIS WAY}}. It was validated with {{THIS}}.

  This detects {{X Y Z}}


  = Limitations

  - Replay attack is undetectable if timing is not considered.

  = Future Work

  - Rotating key for switches for detecting replay attacks (holy shit this is hard)
  - Include (entrance or exit) port in hash

  #bibliography("bib.yml")

]
