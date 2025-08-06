from scapy.all import *


class HostScanner:
    
    """A class to perform various types of network scans.
    This class uses Scapy to perform ARP, ICMP, TCP, and UDP scans on a specified IP range.
    """

    def __init__(self, ip_range, timeout):
        self.ip_range = ip_range
        self.timeout = timeout
    
    def send_icmp_ping(self):

        try: 
            """Sends ICMP ping requests to the specified IP range."""
            ans, unans = sr(IP(dst=self.ip_range)/ICMP(), timeout=self.timeout)
            response = ans.summary(lambda s,r: r.sprintf("%IP.src% is alive") )
            return response

        except Exception as e:
            print(f"An error occurred while sending ICMP ping: {e}")

    def send_arp_ping(self):

        """Sends ARP ping requests to the specified IP range."""
        try:
           ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.ip_range), timeout=self.timeout)
           response = ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
           return response
        except Exception as e:
            print(f"An error occurred while sending ARP ping: {e}")


