from scapy.all import *
from netaddr import IPNetwork
import asyncio

class Scanner:
    #
    # ----------------- To Do List -----------------
    # - On TCP SYN Ping, add more ports to scan
    #

    """A class to perform various types of network scans.
    This class uses Scapy to perform ARP, ICMP, TCP, and UDP scans on a specified IP range.
    """
    #
    # ----------------- Initialization -----------------
    #

    def __init__(self, ip_range, timeout):
        self.ip_range = ip_range
        self.timeout = timeout
    
    #
    # ----------------- ICMP Ping -----------------
    #
    
    async def send_icmp_ping(self, ip):
        """Sends an ICMP ping to the specified IP asynchronously."""
        try:
            packet = IP(dst=ip)/ICMP()
            response, _ = await asyncio.to_thread(sr, packet, timeout=self.timeout, verbose=0)
            if response:
                summary = response.summary(lambda s, r: r.sprintf("%IP.src% is alive"))
                if summary:  # Only return non-empty summaries
                    return summary
            return None
        except Exception as e:
            return None  # Silently ignore errors to avoid clutter

    async def run_icmp_ping(self):
        """Runs the ICMP ping asynchronously for all IPs in the range."""
        try:
            tasks = []
            for ip in IPNetwork(self.ip_range):
                tasks.append(self.send_icmp_ping(str(ip)))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [result for result in results if result is not None]
        except Exception as e:
            return []


    #
    # ----------------- ARP Ping ----------------- 
    #
    async def send_arp_ping(self, ip):
        """Sends an ARP ping to the specified IP asynchronously."""
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
            response, _ = await asyncio.to_thread(srp, packet, timeout=self.timeout, verbose=0)
            if response:
                summary = response.summary(lambda s, r: r.sprintf("%Ether.src% %ARP.psrc%"))
                if summary:  # Only return non-empty summaries
                    return summary
            return None
        except Exception as e:
            return None  # Silently ignore errors to avoid clutter

    async def run_arp_ping(self):
        """Runs the ARP ping asynchronously for all IPs in the range."""
        try:
            tasks = []
            for ip in IPNetwork(self.ip_range):
                tasks.append(self.send_arp_ping(str(ip)))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [result for result in results if result is not None]
        except Exception as e:
            return []

    
    #
    # ----------------- TCP SYN Ping ----------------- 
    # Note: Need to update for scanning more ports
    async def send_tcp_syn_ping(self,ip, port):
      
      """Sends a TCP SYN ping to the specified IP and port."""
      packet = IP(dst=ip)/TCP(dport=port, flags="S")
      response = await asyncio.to_thread(sr1,packet, timeout=self.timeout)

      if response and response.haslayer(TCP):
          if response[TCP].flags == 0x12:
                return f"Port {port} is open on {self.ip_range}"
          return None
      
    async def run_tcp_syn_ping(self):

        """Runs the TCP SYN ping asynchronously for all IPs in the range."""
        tasks = []
        for ip in IPNetwork(self.ip_range):
            tasks.append(self.send_tcp_syn_ping(str(ip), 80))
        
        results = await asyncio.gather(*tasks)
        return [result for result in results if result is not None]

    #
    # ----------------- UDP Ping -----------------
    # Note: Need to update for scanning more ports
    async def send_udp_ping(self, ip, port):
        """Sends a UDP ping to the specified IP and port."""
        packet = IP(dst=ip)/UDP(dport=port)
        response = await asyncio.to_thread(sr1, packet, timeout=self.timeout)

        if response and response.haslayer(UDP):
            return f"Port {port} is open on {self.ip_range}"
        return None
    async def run_udp_ping(self):
        """Runs the UDP ping asynchronously for all IPs in the range."""
        tasks = []
        for ip in IPNetwork(self.ip_range):
            tasks.append(self.send_udp_ping(str(ip), 53))
        results = await asyncio.gather(*tasks)
        return [result for result in results if result is not None]
