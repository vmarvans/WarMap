import HostScanner as HS
import asyncio

if __name__ == "__main__":

    host_scanner = HS.Scanner("192.168.1.0/24", 3)  # Buraya kendi IP aralığını ve arayüz adını yaz

    tcp_results = asyncio.run(host_scanner.run_icmp_ping())
    for result in tcp_results:
        print(result)
 