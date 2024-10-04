#set text(font: "New Computer Modern", size: 12pt)

#let midsection(it) = align(center, text(size: 1.1em, weight: "bold", it))

#midsection[
  #image("ufes_brasao_vertical_cor_rgb.svg", height: 0.82in)

  Universidade Federal do Espírito Santo\
  Colegiado do Curso de Ciência da Computação\
  Trabalho de Conclusão de Curso I\
  Opção 2: Desenvolvimento de um Protótipo

  RELATÓRIO DE RESULTADOS PARCIAIS
]

#text(weight: "bold")[
  Estudante: Henrique Coutinho Layber\
  Orientador: Roberta Lima Gomes
]

= INTRODUÇÃO

Este trabalho tem como objetivo apresentar uma implementação de um mecanismo de sondagem e validação de rota para o protocolo de roteamento de origem (Source Routing) PolKA, com ênfase em redes definidas por software (Software Defined Networks). O mecanismo é baseado em uma composição de funções de checksum em switches de núcleo, que permite a uma parte confiável verificar se um pacote percorreu a rede ao longo do caminho definido pela origem. A validação garante que a rota está funcionando e está configurada corretamente.

O projeto foi desenvolvido como parte do Trabalho de Conclusão de Curso (TCC), que visa integrar os conhecimentos adquiridos ao longo da graduação em uma aplicação prática e relevante. O sistema é capaz de corretamente invalidar pacotes que sofrem de adição de switches, detours e outras formas de ataques, e é capaz de validar corretamente pacotes que seguem o caminho correto. Será elaborada uma extensão para uma conferência na área de redes, e é também uma contribuição para um sistema com desenvolvimento em andamento, PathSec@pathsec.
