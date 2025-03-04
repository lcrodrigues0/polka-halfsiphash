from .siphash import siphash
from .polka_nhop import NODES, Node
from hashlib import sha256

edge_nodes = [f"e{i}" for i in range(1, 11)]

polka_route_ids = {
    "h1": {
        "h1": 0,
        "h2": 2147713608,
        "h3": 103941321831683,
        "h4": 11476003314842104240,
        "h5": 51603676627500816006703,
        "h6": 53859119087051048274660866727,
        "h7": 2786758700157712044095728923460252,
        "h8": 152639893319959825741646821899524043963,
        "h9": 18161241477108940830924939053933556023686562,
        "h10": 40134688781405407356790831164801586774996990884,
    }
}

def calc_digests(route_id: int, node_id: str, seed: int) -> list:
    """Calculates the digest for each node in the path.
    Returns a list of digests.

    @param node The name or index of the node to start from. If hostname is `s1`, index should be `1`.
    """
    if node_id in edge_nodes:
        node_id = f"s{node_id[1:]}"

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


def hash_flow_id(ip_src, port_src, ip_dst, port_dst):
    concat = ip_src + port_src + ip_dst + port_dst
    hash_object = sha256(concat.encode())
    hash_hex = hash_object.hexdigest()
    
    return hash_hex

def calc_flow_id(pkt):
    ip_pkt = pkt.getlayer("IP")
    assert ip_pkt is not None, "❌ IP layer not found"

    tcp_pkt = pkt.getlayer("TCP")
    if tcp_pkt is None:
        port_src = "0"
        port_dst = "0"
    else:
        port_src = tcp_pkt.sport
        port_dst = tcp_pkt.dport

    ip_src = ip_pkt.src
    ip_dst = ip_pkt.dst

    return hash_flow_id(ip_src, port_src, ip_dst, port_dst)

def get_ingress_edge(pkt):
    import re 
    pattern = r"\S\d+"
    match = re.search(pattern, pkt.sniffed_on)

    if match:
        return match.group() 
    else:
        return "s1"