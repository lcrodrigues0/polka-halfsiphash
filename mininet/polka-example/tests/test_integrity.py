from mininet.log import info
from mn_wifi.net import Mininet_wifi


def test_integrity(net: Mininet_wifi):
    """
    Test the integrity of the network, this is to be used in a suite of tests
    """

    def hunt_host(net: Mininet_wifi, name: str):
        for host in net.hosts:
            if host.name == name:
                return host
        return None

    first_host = hunt_host(net, "h1")
    assert first_host is not None, "Host h1 not found"

    last_host = hunt_host(
        net, "h10"
    )  # h11 is right beside h1, so wouldn't traverse all switches
    assert last_host is not None, "Host h10 not found"

    info(
        "*** Testing network integrity\n"
        f"    a ping from {first_host.name} to {last_host.name},\n"
        "    goes through all core switches.\n"
    )

    packet_loss_pct = net.ping(hosts=[first_host, last_host], timeout=1)
    # Comparing floats (bad), but it's fine because an exact 0.0% packet loss is expected
    assert packet_loss_pct == 0.0, f"Packet loss occurred: {packet_loss_pct}%"

