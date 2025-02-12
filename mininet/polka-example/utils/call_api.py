from linear_topology import Polka, PolkaProbe
import urllib
import json
from utils.check_digest import BASE_DIGESTS

ENDPOINT_URL = "http://localhost:5000/"

def call_deploy_flow_contract(flowId):
    print("\n*** Deploying the contract related to the flowId")

    data_dct = {
        "flowId": str(flowId),
        "routeId": "1",
        "edgeAddr": "0xE77227b626394C7c215Ba750f04544E7F0fca68C"
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

def call_set_ref_sig(pkt):
    print("\n*** Registering signature reference")

    polka_pkt = pkt.getlayer(Polka)
    probe_pkt = pkt.getlayer(PolkaProbe)

    data_dct = {
        "flowId": "0",
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
        print("Transaction hash: " + res.read().decode('utf-8').strip())

def call_log_probe(pkt):
    print("\n*** Logging probe signature")

    polka_pkt = pkt.getlayer(Polka)
    probe_pkt = pkt.getlayer(PolkaProbe)

    data_dct = {
        "flowId": "0",
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
        print("Transaction hash: " + res.read().decode('utf8').strip())