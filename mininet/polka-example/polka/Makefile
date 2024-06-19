P4C = p4c
CORE = polka-core.p4
EDGE = polka-edge.p4
ATTACKER = polka-attacker.p4
COMPROMISED = polka-compromised.p4

all: build compromised attacker

build: edge
	${P4C} ${CORE}

edge:
	${P4C} ${EDGE}

compromised:
	${P4C} ${COMPROMISED}

attacker:
	${P4C} ${ATTACKER}
