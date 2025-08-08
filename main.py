import scanner 
import asyncio

if __name__ == "__main__":

    host_scanner = scanner.HostScanner("192.168.1.0/24", 3)  # Buraya kendi IP aralığını ve arayüz adını yaz

    tcp_results = asyncio.run(host_scanner.run_udp_ping())
    for result in tcp_results:
        print(result)
