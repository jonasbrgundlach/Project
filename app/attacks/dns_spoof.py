from scapy.all import *
from utils.poison_gateway_router import poison_gateway_router
def run(args):

    poison_gateway_router(args.victim_ip, args.victim_mac, args.attacker_mac, args.interface)
    
