from linear_topology import Polka, PolkaProbe
import urllib
import json
from utils.check_digest import BASE_DIGESTS

ENDPOINT_URL = "http://localhost:5000/"
EDGE_NODE_ADDRESS = "0xC6e6D46b2139b942FD5fdAaa38B1976308E018a9"

def call_deploy_flow_contract(flowId, pkt):
    print("\n*** Deploying the contract related to the flowId")

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
        print("Successfully deployed:")
        print("Transaction hash: " + res.read().decode('utf-8').strip())

def call_set_ref_sig(flowId, pkt):
    print("\n*** Registering reference signature")

    polka_pkt = pkt.getlayer(Polka)
    probe_pkt = pkt.getlayer(PolkaProbe)

    data_dct = {
        "flowId": str(flowId),
        "routeId": str(polka_pkt.route_id),
        "timestamp": str(probe_pkt.timestamp),
        "lightMultSig": str(hex(BASE_DIGESTS["h1-h10"][probe_pkt.l_hash][10])),
    }

    req = urllib.request.Request(
        ENDPOINT_URL + "setRefSig",
        data = json.dumps(data_dct).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    res = urllib.request.urlopen(req)

    if res.status== 201:
        print("Successfully registered:")
        print("Reference Signature: "  + data_dct["lightMultSig"])
        print("Transaction hash: " + res.read().decode('utf-8').strip())

def call_log_probe(flowId, pkt):
    print("\n*** Logging probe signature")

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
    res = urllib.request.urlopen(req)
   
    if res.status== 201:
        print("Successfully logged:")
        print("Probe Signature: " + data_dct["lightMultSig"])
        print("Transaction hash: " + res.read().decode('utf8').strip())