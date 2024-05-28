# main.py

import argparse
from attacks import arp_poison
from utils import network_utils

def main():
    parser = argparse.ArgumentParser(description="Multi-attack Program")
    subparsers = parser.add_subparsers(dest="attack", help="Type of attack to perform")

    # ARP Poisoning attack arguments
    arp_parser = subparsers.add_parser("arp_poison", help="Perform ARP poisoning attack")
    arp_parser.add_argument("--victim-ip", required=True, help="IP address of the victim's machine")
    arp_parser.add_argument("--victim-mac", required=True, help="MAC address of the victim's machine")
    arp_parser.add_argument("--gateway-ip", required=True, help="IP address of the gateway")
    arp_parser.add_argument("--gateway-mac", required=True, help="MAC address of the gateway")
    arp_parser.add_argument("--attacker-mac", required=True, help="MAC address of the attacker's machine")
    arp_parser.add_argument("--interface", default="eth0", help="Network interface to use for sending ARP packets")

    # Another attack arguments
    another_attack_parser = subparsers.add_parser("another_attack", help="Perform another type of attack")
    another_attack_parser.add_argument("--example-param", required=True, help="Example parameter for another attack")
    
    # Get MAC address arguments
    mac_parser = subparsers.add_parser("get_mac", help="Get the MAC address of a machine using its IP address")
    mac_parser.add_argument("--ip", required=True, help="IP address of the machine to find the MAC address for")
    mac_parser.add_argument("--network-range", required=True, help="The range of IP addresses to scan, e.g., '192.168.56.0-255'")

    # Parse the arguments
    args = parser.parse_args()
    
    # Check which attack to perform
    if args.attack == "arp_poison":
        arp_poison.run(args)
    elif args.attack == "another_attack":
        another_attack.run(args)
    elif args.attack == "get_mac":
        mac_address = network_utils(args.ip, args.network_range)
        if mac_address:
            print("The MAC address for IP {} is {}".format(args.ip, mac_address))
        else:
            print("No MAC address found for IP {}".format(args.ip))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
