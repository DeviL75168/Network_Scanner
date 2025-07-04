import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp
from manuf import MacParser
from typing import List, Dict, Optional
import dpkt
import nmap
try:
    from scanner.utils.oui_db import OUILookup  # when running as installed package
except ImportError:
    from utils.oui_db import OUILookup  # fallback for direct execution
from .utils.ports_db import COMMON_PORTS
from .utils.logger import setup_logger

logger = setup_logger("scanner")

class AdvancedNetworkScanner:
    def __init__(self, threads: int = 100):
        self.threads = threads
        self.mac_parser = MacParser()
        self.oui_db = OUILookup()
        
    def arp_scan(self, ip_range: str) -> List[Dict[str, str]]:
        """Enhanced ARP scan with vendor detection"""
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), 
                    timeout=3, verbose=0)
        return [{
            'ip': rcvd.psrc,
            'mac': rcvd.hwsrc,
            'vendor': self.oui_db.lookup(rcvd.hwsrc)
        } for _, rcvd in ans]

    def threaded_port_scan(self, target: str, ports: List[int]) -> Dict[int, Dict]:
        """Advanced threaded port scanner with service detection"""
        def probe_port(port: int) -> Optional[Dict]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((target, port)) == 0:
                        service = self._detect_service(target, port)
                        return {'port': port, 'service': service}
            except Exception as e:
                logger.error(f"Port {port} scan error: {e}")
            return None

        open_ports = {}
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(probe_port, port) for port in ports]
            for future in as_completed(futures):
                if (result := future.result()) is not None:
                    open_ports[result['port']] = result['service']
        return open_ports

    def _detect_service(self, ip: str, port: int) -> Dict:
        """Deep service detection using NMAP and packet analysis"""
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, str(port), arguments='-sV --version-intensity 3')
            return {
                'name': nm[ip]['tcp'][port]['name'],
                'product': nm[ip]['tcp'][port]['product'],
                'version': nm[ip]['tcp'][port]['version']
            }
        except:
            return {'name': COMMON_PORTS.get(port, 'unknown')}