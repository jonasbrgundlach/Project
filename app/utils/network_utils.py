import subprocess
import re
import socket
import struct
import fcntl

def get_local_ip(interface='eth0'):
    """
    Get the local IP address of the specified network interface.

    Parameters:
    interface (str): Network interface to get the IP address for (default is 'eth0').

    Returns:
    str: Local IP address.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        sock.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', interface[:15])
    )[20:24]
    return socket.inet_ntoa(ip)

def get_network_range(interface='eth0'):
    """
    Get the network range of the specified network interface.

    Parameters:
    interface (str): Network interface to get the network range for (default is 'eth0').

    Returns:
    str: Network range.
    """
    ip = get_local_ip(interface)
    netmask = get_netmask(interface)
    network_range = "{}/{}".format(ip, netmask_to_cidr(netmask))
    return network_range

def get_netmask(interface='eth0'):
    """
    Get the subnet mask of the specified network interface.

    Parameters:
    interface (str): Network interface to get the subnet mask for (default is 'eth0').

    Returns:
    str: Subnet mask.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    netmask = fcntl.ioctl(
        sock.fileno(),
        0x891b,  # SIOCGIFNETMASK
        struct.pack('256s', interface[:15])
    )[20:24]
    return socket.inet_ntoa(netmask)

def netmask_to_cidr(netmask):
    """
    Convert a subnet mask to CIDR notation.

    Parameters:
    netmask (str): Subnet mask.

    Returns:
    int: CIDR notation.
    """
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def get_mac_address(ip, network_range=None, interface='eth0'):
    """
    Function to get the MAC address of a machine using its IP address by scanning the network with nmap.

    Parameters:
    ip (str): IP address of the machine to find the MAC address for.
    network_range (str): The range of IP addresses to scan, e.g., "192.168.56.0-255". If not provided, it will be determined automatically.
    interface (str): Network interface to use for determining the network range if not provided (default is 'eth0').

    Returns:
    str: The MAC address of the machine with the specified IP address, or None if not found.
    """
    try:
        if network_range is None:
            network_range = get_network_range(interface)
        
        # Run the nmap command
        nmap_output = subprocess.check_output(['nmap', '-sn', network_range])
        
        # Decode the output to a string
        nmap_output = nmap_output.decode('utf-8')
        
        # Use regex to find the MAC address corresponding to the given IP
        ip_pattern = re.compile(r"Nmap scan report for {}".format(re.escape(ip)))
        mac_pattern = re.compile(r"MAC Address: ([0-9A-F:]{17})")

        ip_match = ip_pattern.search(nmap_output)
        if ip_match:
            mac_match = mac_pattern.search(nmap_output, ip_match.end())
            if mac_match:
                return mac_match.group(1)
        
        return None
    except subprocess.CalledProcessError as e:
        print("Error running nmap: {}".format(e))
        return None