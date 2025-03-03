from .siphash import siphash
from .polka_nhop import NODES, Node


def calc_digests(route_id: int, node_id: str, seed: int) -> list:
    """Calculates the digest for each node in the path.
    Returns a list of digests.

    @param node The name or index of the node to start from. If hostname is `s1`, index should be `1`.
    """

    if isinstance(node_id, str):
        node = [n for n in NODES if n.name == node_id][0]
    else:
        raise ValueError("Invalid `node_id` parameter")

    digests = [seed.to_bytes(4, byteorder="big")]
    visited_nodes = []
    while True:
        if node in visited_nodes:
            raise ValueError(f"Loop detected. Visited {visited_nodes!r}")
        visited_nodes.append(node)

        exit_port = node.nhop(route_id)
        keystr = f"{node.node_id:016b}{exit_port:09b}{seed:032b}{0:07b}"
        key = int(keystr, base=2).to_bytes(8, byteorder="big")
        # print(f"key: 0x{key.hex()}")

        new_digest = siphash(key, digests[-1])
        digests.append(new_digest)
        # print(f"{node.name} => 0x{digests[-1].hex()}")

        if exit_port < 2:
            # This means the packet has reached the edge
            # print(f"EXIT PORT {exit_port} on {node.name}")
            break
        next_node = node.ports[exit_port]
        assert isinstance(next_node, Node), f"Invalid next node: {next_node}"
        node: Node = next_node

    return digests
