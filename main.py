import scanner 

if __name__ == "__main__":

    host_scanner = scanner.HostScanner("192.168.1.0/24", "Ethernet", 3)  # Buraya kendi IP aralığını ve arayüz adını yaz

    print(host_scanner.send_icmp_ping())  # ICMP ping gönder
