import dpkt
from collections import defaultdict

class TrafficAnalyzer:
    def analyze_pcap(self, pcap_file):
        """Analyze network traffic patterns"""
        flows = defaultdict(lambda: {'bytes': 0, 'packets': 0})
        
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    flow_key = (ip.src, ip.dst, ip.p)
                    flows[flow_key]['bytes'] += len(ip.data)
                    flows[flow_key]['packets'] += 1
                    
        return flows