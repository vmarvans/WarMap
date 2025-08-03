
import scanner as scanner


if __name__ == "__main__":
    dhcp_scanner = scanner.DHCPScanner("Ethernet")  # Buraya kendi arayüz adını yaz (örnek: "eth0", "wlan0")
    dhcp_scanner.send_discover()
    dhcp_scanner.listen_response()
