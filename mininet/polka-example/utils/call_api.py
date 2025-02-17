from linear_topology import Polka, PolkaProbe
import urllib
import json
from utils.check_digest import BASE_DIGESTS

ENDPOINT_URL = "http://localhost:5000/"
EDGE_NODE_ADDRESS = "0x4dee87c73bC8fc1FE6F32900599961F0767D0993"

def call_deploy_flow_contract(flowId, pkt):
    print(f"\n*** Deploying the contract related to the flowId {flowId}")

    polka_pkt = pkt.getlayer(Polka)

    data_dct = {
        "flowId": str(flowId),
        "routeId": str(polka_pkt.route_id),
        "edgeAddr": EDGE_NODE_ADDRESS
    }

    req = urllib.request.Request(
        ENDPOINT_URL + "/deployFlowContract",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req)

    if(res.status == 201):
        print("Successfully deployed!")
        print("Transaction hash: " + res.read().decode('utf-8').strip())

def call_set_ref_sig(flowId, pkt, path):
    print("* Registering reference signature")

    polka_pkt = pkt.getlayer(Polka)
    probe_pkt = pkt.getlayer(PolkaProbe)

    data_dct = {
        "flowId": str(flowId),
        "routeId": str(polka_pkt.route_id),
        "timestamp": str(probe_pkt.timestamp),
        "lightMultSig": str(hex(BASE_DIGESTS[f"{path[0]}-{path[1]}"][probe_pkt.l_hash][10])),
    }

    req = urllib.request.Request(
        ENDPOINT_URL + "setRefSig",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req)

    if res.status== 201:
        print("Successfully registered!")
        print("Reference Signature: "  + data_dct["lightMultSig"])
        print("Transaction hash: " + res.read().decode('utf-8').strip())

def call_log_probe(flowId, pkt):
    print("\n* Logging probe signature")

    polka_pkt = pkt.getlayer(Polka)
    probe_pkt = pkt.getlayer(PolkaProbe)

    data_dct = {
        "flowId": str(flowId),
        "routeId": str(polka_pkt.route_id),
        "timestamp": str(probe_pkt.timestamp),
        "lightMultSig": str(hex(probe_pkt.l_hash)),   
    }

    req = urllib.request.Request(
        ENDPOINT_URL + "logProbe",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )

    try:
        res = urllib.request.urlopen(req)
        print("Successfully logged!")
        print("Probe Signature: " + data_dct["lightMultSig"])
        print("Transaction hash: " + res.read().decode('utf8').strip())
    except urllib.error.HTTPError as e:
        if e.code == 500:
            print("Erro: " + e.read().decode('utf-8'))
    