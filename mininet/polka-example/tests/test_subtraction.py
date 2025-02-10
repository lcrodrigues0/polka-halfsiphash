def test_subtraction():
    """
    Test if the network is protected against a subtraction attack.

    A subtraction attack is when a switch is skipped in the route,
    and the packets are sent directly to the next switch in the route.
    """
