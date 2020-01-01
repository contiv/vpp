"""
Library to make simple python functions as robot keywords
"""
import ipaddress

def get_ip_version(ip_string):
    """Get ip version as integer number"""
    ip = ipaddress.ip_address(unicode(ip_string))
    return ip.version
