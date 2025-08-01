import scapy.all as scapy

class HostScanner:
    def __init__(self, ip_range, network_interface, timeout):
        self.ip_range = ip_range
        self.network_interface = network_interface
        self.timeout = timeout
    
    def arp_ping(self):

        arp_request = scapy.arping(self.ip_range,
                                   iface=self.network_interface,
                                   timeout=self.timeout,)
        return arp_request
    
if __name__ == "__main__":
    scanner = HostScanner("192.168.1.0/24", "Ethernet", 2)
    result = scanner.arp_ping()
    print(result)