from scapy.all import *

def find_gateway_ip():
    """
    Function to find the default gateway IP address on the local network.

    Returns:
    str: IP address of the default gateway.
    """
    # Perform a route lookup to get the gateway IP
    route = conf.route.route("0.0.0.0")[2]
    return route

