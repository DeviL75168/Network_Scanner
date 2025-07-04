import pickle
import numpy as np
from scapy.all import IP, TCP

class DeviceClassifier:
    def __init__(self):
        with open('ml/model.pkl', 'rb') as f:
            self.model = pickle.load(f)
            
    def extract_features(self, pkt):
        """Extract 50+ network features for ML"""
        features = []
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip = pkt[IP]
            tcp = pkt[TCP]
            features.extend([
                ip.ttl,
                len(tcp.options),
                tcp.window,
                int(tcp.flags == 0x12)  # SYN-ACK
            ])
        return np.array(features)
    
    def predict(self, pkt):
        """Predict device type"""
        return self.model.predict([self.extract_features(pkt)])[0]