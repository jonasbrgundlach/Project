# main.py

import argparse
from attacks import arp_poison

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

    args = parser.parse_args()
    
    # Check which attack to perform
    if args.attack == "arp_poison":
        arp_poison.run(args)
    elif args.attack == "another_attack":
        print("Performing another attack with parameter: %s" % args.example_param)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
