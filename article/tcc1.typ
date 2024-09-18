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

#lorem(150)

#midsection[Keywords]

#{
  let keyword_sep = [; ]
  let keywords = ("Verifiable Routing", "Path Verification", "Proof-of-transit", "In-networking Programming")
  text(weight: "bold", keywords.join(keyword_sep))
}

#columns(2)[
  = Introduction

  Ever since Source Routing (SR) was proposed, there has been a need to ensure that packets traverse the network along the paths selected by the source, not only for security reasons but also to ensure that the network is functioning correctly and correctly configured. This is particularly important in the context of Software-Defined Networking (SDN), where the control plane can select paths based on a variety of criteria.

  In this paper, we propose a new implementation for Verifiable Routing on a protocol layer for PolKA. It is available on GitHub#footnote[https://github.com/Henriquelay/polka-halfsiphash/tree/remake/mininet/polka-example]. This is achieved by using a composition of intermediate hashes on core switches, each using a secret key (`switch_id`) to generate a result hash that can be checked by the controller which knows the secrets. The controller can then verify that the packet traversed the network along the path selected by the source, ensuring that the network is functioning correctly.

  = Related Works
  // does this section makes sense?

  #lorem(100)

  = Problem Definition

  #figure(
    caption: [Topology setup],
    diagram(
      node-stroke: 0.5pt,
      node-inset: 4pt,
      // debug: 1,
      spacing: 1em,
      {
        let switch = node.with(shape: shapes.octagon, fill: aqua)
        let edge_router = node.with(shape: shapes.pill, fill: lime)
        let host = node.with(shape: shapes.rect, fill: yellow)

        let first_1 = 1
        let last_1 = 3
        for i in range(first_1, last_1+1) {
          let h = "h" + str(i)
          host((i, 2), name: label(h))[#h]
          edge("<->")
          let e = "e" + str(i)
          edge_router((i, 1), name: label(e))[#e]
          edge("<->")
          let s = "s" + str(i)
          switch((i, 0), name: label(s))[#s]
          if i > first_1 {
            edge(label("s" + str(i - 1)), label("s" + str(i)), "<->")
          }
        }

        let first = -2
        let offset = 1
        let lim = range(first, 1)
        for i in lim {
          host(
            (rel: (offset + i + lim.len(), 0), to: label("h" + str(last_1))),
            name: label("hn" + str(-i)),
          )[$h_(n#{
            if i == 0 {
              ""
            } else {
              i
            }
        })$]

          edge("<->")

          edge_router(
            (rel: (offset + i + lim.len(), 0), to: label("e" + str(last_1))),
            name: label("en" + str(-i)),
          )[$e_(n#{
            if i == 0 {
              ""
            } else {
              i
            }
        })$]

          edge("<->")

          switch(
            (rel: (offset + i + lim.len(), 0), to: label("s" + str(last_1))),
            name: label("sn" + str(-i)),
          )[$s_(n#{
            if i == 0 {
              ""
            } else {
              i
            }
        })$]
          if i > first {
            edge(label("sn" + str(-i + 1)), label("sn" + str(-i)), "<->")
          }
        }

        node((rel:(0, 0), to: (label("s" + str(last_1)), 50%, label("sn"+str(-first)))), stroke: none)[...]
        edge(label("sn"+str(-first)), "<->")
        edge(label("s" + str(last_1)), "<->")
        node((rel:(0, 0), to: (label("h" + str(last_1)), 50%, label("hn"+str(-first)))), stroke: none)[...]
        node((rel:(0, 0), to: (label("e" + str(last_1)), 50%, label("en"+str(-first)))), stroke: none)[...]

        node((rel: (0pt, 24pt), to: (<s1>, 50%, <sn0>)), "controller", name: <controller>, shape: shapes.rect, fill: silver)
      },
    ),
  ) <sr-diagram>


  #lorem(200)

  = Path-Aware Secure Routing...
  #lorem(600)

  = Related Works

  #lorem(200)

  = Limitations

  #lorem(150)

  #bibliography("bib.yml")

]
