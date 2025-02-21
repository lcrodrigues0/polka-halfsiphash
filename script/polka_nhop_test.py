from .polka_nhop import NODES

import pytest


def test_nhop():
    assert NODES[1].nhop(51603676627500816006703) == 2
    for node in NODES[2:4]:
        print(node.name)
        assert node.nhop(51603676627500816006703) == 3
    assert NODES[5].nhop(51603676627500816006703) == 1


@pytest.mark.parametrize(
    "route_id,to",
    [
        (2147713608, 2),
        (103941321831683, 3),
        (11476003314842104240, 4),
        (51603676627500816006703, 5),
        (53859119087051048274660866727, 6),
        (2786758700157712044095728923460252, 7),
        (152639893319959825741646821899524043963, 8),
        (18161241477108940830924939053933556023686562, 9),
        (40134688781405407356790831164801586774996990884, 10),
    ],
)
def test_route_from_s1(route_id, to):
    print(NODES[1].name)
    assert NODES[1].nhop(route_id) == 2, "First node should hop to next"

    for node in NODES[2 : to - 1]:
        print(node.name)
        assert node.nhop(route_id) == 3, "Middle nodes should hop to next"

    print(NODES[to].name)
    assert NODES[to].nhop(route_id) == 1, "Last node should hop to edge"

@pytest.mark.parametrize(
    "route_id,to",
    [
        (2147713611, 2),
        (90458134409591, 3),
        (10482717147535550117, 4),
        (51347769747097379570558, 5),
        (55407306396185788809801065734, 6),
        (961828181675098119897094171850651, 7),
        (253331599648734306228086701980157549055, 8),
        (16054688143525084430425025853824039774109490, 9),
        (259209858529954363229779036367232959135105947981, 10),
    ],
)
def test_route_to_s1(route_id, to):
    for node in NODES[to: 2]:
        print(node.name)
        assert node.nhop(route_id) == 2, "Node should hop to previous node"
    
    assert NODES[1].nhop(route_id) == 1, "First node should hop to edge"
