import argparse
import sys
import os

# Ensure the parent directory is in the system path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import attack modules and utility functions
from attacks import arp_poison
from utils.network_utils import get_mac_address

def add_arp_poison_parser(subparsers):
    """
    Add parser for ARP poisoning attack.
    """
    arp_parser = subparsers.add_parser("arp_poison", help="Perform ARP poisoning attack")
    arp_parser.add_argument("--victim-ip", required=True, help="IP address of the victim's machine")
    arp_parser.add_argument("--victim-mac", required=False, help="MAC address of the victim's machine")
    arp_parser.add_argument("--gateway-ip", required=True, help="IP address of the gateway")
    arp_parser.add_argument("--gateway-mac", required=False, help="MAC address of the gateway")
    arp_parser.add_argument("--attacker-mac", required=False, help="MAC address of the attacker's machine")
    arp_parser.add_argument("--interface", default="enp0s3", help="Network interface to use for sending ARP packets")

def add_get_mac_parser(subparsers):
    """
    Add parser for getting MAC address.
    """
    mac_parser = subparsers.add_parser("get_mac", help="Get the MAC address of a machine using its IP address")
    mac_parser.add_argument("--ip", required=True, help="IP address of the machine to find the MAC address for")
    mac_parser.add_argument("--network-range", required=False, help="The range of IP addresses to scan, e.g., '192.168.56.0-255'")
    mac_parser.add_argument("--interface", default="enp0s3", help="Network interface to use if network range is not provided (default: 'enp0s3')")

def main():
    parser = argparse.ArgumentParser(description="Multi-attack Program")
    subparsers = parser.add_subparsers(dest="attack", help="Type of attack to perform")

    # Add subparsers
    add_arp_poison_parser(subparsers)
    add_get_mac_parser(subparsers)

    args = parser.parse_args()

    if args.attack == "arp_poison":
        arp_poison.run(args)
    elif args.attack == "get_mac":
        get_mac_address(args.ip, args.network_range, args.interface)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
