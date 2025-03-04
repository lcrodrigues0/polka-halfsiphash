from urllib import request, error
import json

from script.tester import Polka, PolkaProbe
from script.utils import calc_digests, polka_route_ids, get_ingress_edge, calc_flow_id, hash_flow_id

ENDPOINT_URL = "http://localhost:5000/"
EDGE_NODE_ADDRESS = "0xF00013280116dCCa58FbFDb97a58B0Db7Fe51a98"

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

def call_set_ref_sig(pkt):
    polka_pkt = pkt.getlayer(Polka)
    assert polka_pkt is not None, "❌ Polka layer not found"
    probe_pkt = pkt.getlayer(PolkaProbe)
    assert probe_pkt is not None, "❌ Probe layer not found"

    ingress_edge = get_ingress_edge(pkt)
    flow_id = calc_flow_id(pkt)
    route_id = polka_pkt.route_id
    timestamp = probe_pkt.timestamp
    light_mult_sig = f"0x{calc_digests(route_id, ingress_edge, timestamp)[-1].hex()}"

    data_dct = {
        "flowId": str(flow_id),
        "routeId": str(route_id),
        "timestamp": str(hex(timestamp)),
        "lightMultSig": str(light_mult_sig),
    }

    req = request.Request(
        ENDPOINT_URL + "setRefSig",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )

    try:
        res = request.urlopen(req)
        print("\n*** Registering reference signature in flow " + flow_id)
        print("Reference Signature: "  + data_dct["lightMultSig"])
        print("Transaction hash: " + res.read().decode('utf-8').strip(), end="\n\n")
    except error.HTTPError as e:
        if e.code == 500:
            print("\n*** Registering reference signature in flow " + flow_id)
            print("Erro: " + e.read().decode('utf-8'))        
    

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
        "timestamp": str(hex(timestamp)),
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
    