import subprocess
import re

def get_mac_address(ip, network_range):
    """
    Function to get the MAC address of a machine using its IP address by scanning the network with nmap.

    Parameters:
    ip (str): IP address of the machine to find the MAC address for.
    network_range (str): The range of IP addresses to scan, e.g., "192.168.56.0-255".

    Returns:
    str: The MAC address of the machine with the specified IP address, or None if not found.
    """
    try:
        # Run the nmap command
        nmap_output = subprocess.check_output(['nmap', '-sn', network_range])
        
        # Decode the output to a string
        nmap_output = nmap_output.decode('utf-8')
        
        # Use regex to find the MAC address corresponding to the given IP
        ip_pattern = re.compile(r"^Nmap scan report for {}".format(re.escape(ip)), re.MULTILINE)
        mac_pattern = re.compile(r"MAC Address: ([0-9A-F:]{17})", re.MULTILINE)

        ip_match = ip_pattern.search(nmap_output)
        if ip_match:
            mac_match = mac_pattern.search(nmap_output, ip_match.end())
            if mac_match:
                return mac_match.group(1)
        
        return None
    except subprocess.CalledProcessError as e:
        print("Error running nmap: {}".format(e))
        return None
