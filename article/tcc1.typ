#set text(font: "New Computer Modern", size: 11pt)
#set par(justify: true)

#let midsection(it) = align(center, text(size: 12pt, weight: "bold", it))
#let title = [Verifiable Routing on PolKA]

#let deptInfUFESsym = sym.ast.basic
#let deptInfIFESsym = sym.dagger
#let deptInfUFES(it) = box([#it#deptInfUFESsym])
#let deptInfIFES(it) = box([#it#deptInfIFESsym])

#let authors = [
  #set par(justify: false)
  #deptInfUFES[Henrique C. Layber], #deptInfUFES[Roberta Lima Gomes], #deptInfUFES[Magnos Martinello], #deptInfUFES[Vitor B. Bonella], #deptInfIFES(deptInfUFES[Rafael Guimarães]), #deptInfIFES[Everson S. Borges]]

#midsection(text(size: 18pt, title))

#align(center, par(justify: false)[#authors])

#align(center)[
  #deptInfUFESsym\Department of Informatics, Federal University of Espírito Santo \ #deptInfIFESsym\Department of Informatics, Federal Institute of Espírito Santo
]

#midsection[Abstract]

#lorem(150)

#midsection[Keywords]

#lorem(10)

#set text(weight: "regular")

#set heading(numbering: "I.1.a")

#columns(2)[
  = Introduction


  @polka #lorem(300)

  = Problem Definition

  #lorem(200)

  = Path-Aware Secure Routing...
  #lorem(600)

  = Related Works

  #lorem(200)

  = Limitations

  #lorem(150)
]
#bibliography("bib.yml")
