
def enable_ip_forwarding():
    """
    Enable IP forwarding on the attacker's machine.
    """
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        print("IP forwarding enabled.")
    except Exception as e:
        print("Failed to enable IP forwarding: %s" % str(e))

def disable_ip_forwarding():
    """
    Disable IP forwarding on the attacker's machine.
    """
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
        print("IP forwarding disabled.")
    except Exception as e:
        print("Failed to disable IP forwarding: %s" % str(e))