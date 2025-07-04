import nmap
from typing import Optional
import subprocess
from scapy.all import IP, TCP
from .utils.logger import setup_logger

logger = setup_logger("fingerprint")

def os_fingerprint(target_ip: str) -> str:
    """
    Perform OS fingerprinting using Nmap with fallback to passive detection
    Returns: OS name as string
    """
    # Try active Nmap detection first
    try:
        nm = nmap.PortScanner()
        nm.scan(target_ip, arguments="-O --osscan-limit")
        if target_ip in nm.all_hosts():
            os_info = nm[target_ip].get('osmatch', [{}])[0].get('name', 'Unknown')
            if os_info != 'Unknown':
                return os_info
    except Exception as e:
        logger.warning(f"Nmap OS detection failed: {str(e)}")
    
    # Fallback to passive detection
    return passive_fingerprint(target_ip) or "Unknown"

def passive_fingerprint(target_ip: str) -> Optional[str]:
    """
    Passive fingerprinting using network characteristics
    Returns: OS name or None if undetermined
    """
    try:
        # Simple TTL-based detection
        result = subprocess.run(['ping', '-c', '1', target_ip], 
                              capture_output=True, text=True)
        if 'ttl=' in result.stdout.lower():
            ttl = int(result.stdout.lower().split('ttl=')[1].split()[0])
            if ttl <= 64:
                return "Linux/Unix"
            elif 65 <= ttl <= 128:
                return "Windows"
            elif ttl > 128:
                return "Network Device"
    except Exception as e:
        logger.debug(f"Passive fingerprint failed: {str(e)}")
    
    return None