from manuf import manuf
from typing import Optional

class OUILookup:
    def __init__(self):
        self.parser = manuf.MacParser()
        
    def lookup(self, mac_address: str) -> Optional[str]:
        """Lookup vendor from MAC address"""
        try:
            return self.parser.get_manuf(mac_address)
        except:
            return None