import scapy.all as scapy

class DHCPScanner:
    """A class to perform DHCP scanning on a specified network interface.
    This class uses Scapy to send DHCP discover packets and listen for responses.
    """

    def __init__(self, interface):
        self.interface = interface
        self.client_mac = scapy.get_if_hwaddr(interface)


    def send_discover(self):
        dhcp_discover = (
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=self.client_mac) /
            scapy.IP(src="0.0.0.0", dst="255.255.255.255") /
            scapy.UDP(sport=68, dport=67) /
            scapy.BOOTP(chaddr=[int(b, 16) for b in self.client_mac.split(":")] + [0]*10) /
            scapy.DHCP(options=[("message-type", "discover"), "end"])
        )

        print("[*] DHCP Discover paketi gönderiliyor...")
        scapy.sendp(dhcp_discover, iface=self.interface, verbose=0)

    def listen_response(self):
        timeout = 10  # Burada timeout'u tanımlıyoruz

        print(f"[*] {timeout} saniye boyunca DHCP yanıtları dinleniyor...")

        def handle_packet(pkt):
            if pkt.haslayer(scapy.DHCP):
                print("\n[+] DHCP Yanıtı Alındı:")
                pkt.show()

        scapy.sniff(
            iface=self.interface,
            filter="udp and (port 67 or 68)",
            prn=handle_packet,
            timeout=timeout
        )


class HostScanner:
    
    """A class to perform various types of network scans.
    This class uses Scapy to perform ARP, ICMP, TCP, and UDP scans on a specified IP range.
    """

    def __init__(self, ip_range, network_interface, timeout):
        self.ip_range = ip_range
        self.network_interface = network_interface
        self.timeout = timeout
    
    def arp_ping(self):

        arp_request = scapy.arping(self.ip_range,
                                   iface=self.network_interface,
                                   timeout=self.timeout,)
        return arp_request
    
    def icmp_ping(self):

        icmp_request = scapy.sr(scapy.IP(dst=self.ip_range)/scapy.ICMP(),
                                 iface=self.network_interface,
                                 timeout=self.timeout)
        return icmp_request
    
    def tcp_ping(self, port):

        tcp_request = scapy.sr(scapy.IP(dst=self.ip_range)/scapy.TCP(dport=port, flags="S"),
                                 iface=self.network_interface,
                                 timeout=self.timeout)
        return tcp_request
    
    def udp_ping(self, port):

        udp_request = scapy.sr(scapy.IP(dst=self.ip_range)/scapy.UDP(dport=port),
                                 iface=self.network_interface,
                                 timeout=self.timeout)
        return udp_request
    