import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp
from manuf import manuf
from typing import List, Dict, Optional
import nmap
import win32net  # For NetBIOS name resolution
from .utils.logger import setup_logger
from .utils.ports_db import COMMON_PORTS
from scanner.fingerprint import os_fingerprint

logger = setup_logger("network_scanner")

class NetworkScanner:
    def __init__(self, threads: int = 50):
        self.threads = threads
        self.mac_parser = manuf.MacParser()

    def arp_scan(self, ip_range: str) -> List[Dict[str, str]]:
        """ARP scan with automatic vendor detection"""
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=3, verbose=0)
        devices = []
        for _, rcvd in ans:
            mac = rcvd.hwsrc
            devices.append({
                'ip': rcvd.psrc,
                'mac': mac,
                'vendor': self.mac_parser.get_manuf(mac) or "Unknown"
            })
        return devices

    def port_scan(self, target: str, ports: List[int], timeout: int = 1) -> Dict[str, Dict[int, str]]:
        """Multi-threaded port scanner with service detection."""
        open_ports = {}
        
        def scan_port(port: int) -> Optional[tuple[int, str]]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((target, port)) == 0:
                        return port, self.guess_service(port)
            except Exception as e:
                logger.error(f"Error scanning {target}:{port}: {e}")
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in as_completed(futures):
                if (result := future.result()) is not None:
                    port, service = result
                    open_ports[port] = service

        return {target: open_ports}

    def guess_service(self, port: int) -> str:
        """Common port service mapping."""
        return COMMON_PORTS.get(port, "Unknown")


class AdvancedNetworkScanner(NetworkScanner):
    def __init__(self, threads: int = 100):
        super().__init__(threads)
        self.nm = nmap.PortScanner()

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

    def get_netbios_name(self, ip):
        """Get NetBIOS name for Windows devices"""
        try:
            return win32net.Netbios(ip).GetName()
        except:
            return None

    def get_hostname(self, ip_address, timeout=1):
        """Enhanced hostname detection with multiple methods"""
        # Try reverse DNS first
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            if hostname and not hostname.startswith(('localhost', 'ip-')):
                return hostname
        except:
            pass
        
        # Try NetBIOS for Windows devices
        try:
            netbios_name = self.get_netbios_name(ip_address)
            if netbios_name:
                return netbios_name
        except:
            pass
            
        return None

    def _detect_service(self, ip: str, port: int) -> Dict:
        """Deep service detection using NMAP"""
        try:
            self.nm.scan(ip, str(port), arguments='-sV --version-intensity 3')
            return {
                'name': self.nm[ip]['tcp'][port]['name'],
                'product': self.nm[ip]['tcp'][port]['product'],
                'version': self.nm[ip]['tcp'][port]['version']
            }
        except Exception as e:
            logger.warning(f"Service detection failed: {e}")
            return {'name': COMMON_PORTS.get(port, 'unknown')}

    def scan(self, ip_range, ports=None):
        """Complete network scan with ARP, ports, OS and hostname detection"""
        if ports is None:
            ports = list(COMMON_PORTS.keys())
        
        devices = self.arp_scan(ip_range)
        
        # Get hostnames in parallel
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            hostname_futures = {
                executor.submit(self.get_hostname, device['ip']): device 
                for device in devices
            }
            
            for future in as_completed(hostname_futures):
                device = hostname_futures[future]
                device['hostname'] = future.result()
        
        # Get ports and OS info
        for device in devices:
            device['ports'] = self.threaded_port_scan(device['ip'], ports)
            device['os'] = os_fingerprint(device['ip'])
        
        return devices