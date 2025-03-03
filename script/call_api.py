from urllib import request, error
import json
from hashlib import sha256

from script.tester import Polka, PolkaProbe
from script.calc_digests import calc_digests

ENDPOINT_URL = "http://localhost:5000/"
EDGE_NODE_ADDRESS = "0x0cA14F8f0CEB8CD6dbD97d8bA47D572a20ce6004"

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

def call_deploy_flow_contract(flowId, first_host="h1", last_host="h10"):
    print(f"\n*** Deploying the contract related to the flowId {flowId}")

    data_dct = {
        "flowId": str(flowId),
        "routeId": str(polka_route_ids[first_host][last_host]),
        "edgeAddr": EDGE_NODE_ADDRESS
    }

    req = request.Request(
        ENDPOINT_URL + "/deployFlowContract",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = request.urlopen(req)

    if(res.status == 201):
        print("Successfully deployed!")
        print("Transaction hash: " + res.read().decode('utf-8').strip())

    print("\n")


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

def call_set_ref_sig(pkt):
    polka_pkt = pkt.getlayer(Polka)
    assert polka_pkt is not None, "❌ Polka layer not found"
    probe_pkt = pkt.getlayer(PolkaProbe)
    assert probe_pkt is not None, "❌ Probe layer not found"
    
    ingress_edge="s1"
    flow_id = calc_flow_id(pkt)
    route_id = polka_pkt.route_id
    timestamp = probe_pkt.timestamp
    light_mult_sig = f"0x{calc_digests(route_id, ingress_edge, timestamp)[-1].hex()}"

    data_dct = {
        "flowId": str(flow_id),
        "routeId": str(route_id),
        "timestamp": str(timestamp),
        "lightMultSig": str(light_mult_sig),
    }

    req = request.Request(
        ENDPOINT_URL + "setRefSig",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = request.urlopen(req)

    if res.status== 201:
        print("\n*** Registering reference signature in flow " + flow_id)
        print("Reference Signature: "  + data_dct["lightMultSig"])
        print("Transaction hash: " + res.read().decode('utf-8').strip(), end="\n\n")

    

def call_log_probe(pkt):
    polka_pkt = pkt.getlayer(Polka)
    assert polka_pkt is not None, "❌ Polka layer not found"
    probe_pkt = pkt.getlayer(PolkaProbe)
    assert probe_pkt is not None, "❌ Probe layer not found"

    flow_id = calc_flow_id(pkt)
    route_id = polka_pkt.route_id
    timestamp = probe_pkt.timestamp
    light_mult_sig = hex(probe_pkt.l_hash)

    data_dct = {
        "flowId": str(flow_id),
        "routeId": str(route_id),
        "timestamp": str(timestamp),
        "lightMultSig": str(light_mult_sig),   
    }

    req = request.Request(
        ENDPOINT_URL + "logProbe",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )

    try:
        res = request.urlopen(req)
        print("\n*** Logging probe signature in flow " + flow_id)
        print("Probe Signature: " + data_dct["lightMultSig"])
        print("Transaction hash: " + res.read().decode('utf8').strip(), end="\n\n")
    except error.HTTPError as e:
        if e.code == 500:
            print("\n*** Logging probe signature in flow " + flow_id)
            print("Erro: " + e.read().decode('utf-8'))
    