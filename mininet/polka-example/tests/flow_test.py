from mn_wifi.net import Mininet_wifi
from mininet.log import info

def flow_test(net: Mininet_wifi, flowID: str, fst_host_name: str, lst_host_name: str, n_pkts: int):
    def find_host_by_name(net: Mininet_wifi, name: str):
        for host in net.hosts:
            if host.name == name:
                return host
        return None
    

    first_host = find_host_by_name(net, fst_host_name)
    assert first_host is not None, f"Host {fst_host_name} not found."

    last_host = find_host_by_name(net, lst_host_name)
    assert last_host is not None, f"Host {lst_host_name} not found."

    info("*** Flow emulation: ")
    info(f"Ping 10 packets from {fst_host_name} to {lst_host_name}\n\n")

    info("*** Ping Execution\n")
    # packet_loss_pct = net.ping(hosts=[first_host, last_host], timeout=1)
    result = first_host.cmd(f"ping -c {n_pkts} {last_host.IP()}")
    print(result)   

def process_pkts(pkts, n_pkts):
    pkts.sort(key=lambda pkt: pkt.time)

    # Apenas uma interface de cada nó
    pkts = pkts[1::2]

    parts = split_vector(pkts, n_pkts)

    first = []
    last = []
    for part in parts:
        first.append(part[0])
        last.append(part[len(part)//2 - 1])
        
    return first, last 

def split_vector(vector, n):
    length = len(vector)
    slice_len = length // n
    
    parts = []
    start = 0
    
    for i in range(n):
        end = start + slice_len
        parts.append(vector[start:end])
        start = end
    
    return parts