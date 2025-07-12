import json
from nmap import PortScanner
import socket
from packaging.version import Version, InvalidVersion

def scan_ip(target: str, start=1, end=1024):
    ip = socket.gethostbyname(target)
    print(f"Target IP: {ip}")
    scanner = PortScanner()
    result = scanner.scan(ip, f"{start}-{end}", '-sV')
    protocols = result['scan'][ip].all_protocols()
    services = []

    #rint(scanner[ip].all_protocols())
    #print(result)
    #print(protocols)

    for protocol in protocols:
        for port in result['scan'][ip][protocol]:
            service = result['scan'][ip][protocol][port]
            services.append({
                'port': port,
                'name': service.get('name'),
                'product': service.get('product'),
                'version': service.get('version')
            })

    return services

print(scan_ip('scanme.nmap.org'))