import ipaddress
from typing import Union, List

def validate_ip(ip: str) -> bool:
    """Validate an IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_ports(ports: Union[List[int], str]) -> List[int]:
    """Convert port string (e.g., '80,443') to list of integers."""
    if isinstance(ports, str):
        return [int(p.strip()) for p in ports.split(",")]
    return ports