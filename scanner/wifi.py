import platform
import time
import logging
import pandas as pd
from manuf import manuf
from typing import List, Dict, Optional

# Conditional Scapy import with fallback
try:
    from scapy.all import Dot11, Dot11Beacon, sniff, conf
    from scapy.arch.windows import get_windows_if_list
    SCAPY_AVAILABLE = True
except ImportError as e:
    logging.error(f"Scapy import failed: {e}")
    SCAPY_AVAILABLE = False

logger = logging.getLogger("wifi_scanner")

class WiFiScanner:
    def __init__(self, interface: str = None):
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for WiFi scanning. Please install it with: pip install scapy")
            
        self.mac_parser = manuf.MacParser()
        self.interface = self._validate_interface(interface)
        
    def _validate_interface(self, interface: str) -> str:
        """Find and validate a WiFi interface with detailed error handling"""
        if platform.system() != 'Windows':
            raise NotImplementedError("WiFi scanning currently only supported on Windows")
        
        try:
            ifaces = get_windows_if_list()
            if not ifaces:
                raise ValueError("No network interfaces detected")
            
            # Normalize interface names for comparison
            available_ifaces = [iface['name'].strip().lower() for iface in ifaces]
            
            # If specific interface requested
            if interface:
                interface_lower = interface.strip().lower()
                for iface in ifaces:
                    if iface['name'].strip().lower() == interface_lower:
                        logger.info(f"Using specified interface: {iface['name']}")
                        return iface['name']
                raise ValueError(f"Interface '{interface}' not found. Available: {available_ifaces}")
            
            # Auto-detect WiFi interface
            wifi_keywords = ['wi-fi', 'wireless', 'wlan']
            for iface in ifaces:
                if any(kw in iface['name'].lower() for kw in wifi_keywords):
                    logger.info(f"Auto-selected WiFi interface: {iface['name']}")
                    return iface['name']
            
            # Fallback to first interface with warning
            if ifaces:
                logger.warning(f"No clear WiFi interface found, using first available: {ifaces[0]['name']}")
                return ifaces[0]['name']
            
            raise ValueError("No suitable network interfaces found")
            
        except Exception as e:
            logger.error(f"Interface validation failed: {e}")
            raise

    def scan_networks(self, timeout: int = 10) -> pd.DataFrame:
        """Perform WiFi scan with comprehensive error handling"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is not available")
            
        networks = []
        
        def packet_handler(pkt):
            try:
                if pkt.haslayer(Dot11Beacon):
                    ssid = pkt[Dot11].info.decode(errors='ignore') or 'Hidden'
                    bssid = pkt[Dot11].addr2
                    channel = int(ord(pkt[Dot11Elt:3].info)) if pkt.haslayer(Dot11Elt) else 0
                    rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else None
                    
                    networks.append({
                        'SSID': ssid,
                        'BSSID': bssid,
                        'Channel': channel,
                        'Vendor': self.mac_parser.get_manuf(bssid) or "Unknown",
                        'RSSI': rssi,
                        'Encryption': self._get_encryption_type(pkt)
                    })
            except Exception as e:
                logger.debug(f"Error processing WiFi packet: {e}")

        try:
            logger.info(f"Starting WiFi scan on {self.interface} (timeout: {timeout}s)")
            start_time = time.time()
            
            # Configure Scapy
            conf.use_pcap = True
            conf.iface = self.interface
            conf.verb = 0  # Reduce verbosity
            
            # Start sniffing
            sniff(iface=self.interface,
                  prn=packet_handler,
                  timeout=timeout,
                  store=False)
                  
            logger.info(f"Scan completed. Found {len(networks)} networks in {time.time()-start_time:.2f}s")
            
        except Exception as e:
            logger.error(f"WiFi scan failed: {e}")
            raise
            
        return pd.DataFrame(networks) if networks else pd.DataFrame()

    def _get_encryption_type(self, pkt) -> str:
        """Detect WiFi encryption type from packet"""
        try:
            if pkt.haslayer(Dot11Elt):
                if pkt.cap.privacy:
                    return "WPA/WPA2" if pkt.haslayer(Dot11EltRSN) else "WEP"
                return "Open"
            return "Unknown"
        except:
            return "Unknown"

    @staticmethod
    def list_interfaces() -> List[Dict]:
        """List all available network interfaces with details"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required")
            
        try:
            return get_windows_if_list()
        except Exception as e:
            logger.error(f"Interface listing failed: {e}")
            return []