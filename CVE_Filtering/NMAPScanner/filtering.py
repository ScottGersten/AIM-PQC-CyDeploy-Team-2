import json
from nmap import PortScanner
import socket
from packaging.version import Version, InvalidVersion

def scan_ip(target: str, start=1, end=1024):
    ip = socket.gethostbyname(target)
    print(f"Target IP: {ip}")
    scanner = PortScanner()
    result = scanner.scan(ip, f"{start}-{end}", '-sV')
    #result = scanner.scan(ip, f"{start}-{end}", '-sV --version-all --script=banner -T4')
    protocols = result['scan'][ip].all_protocols()
    services = []

    with open('nm_result.json', 'w') as f:
        f.write(json.dumps(result, indent=2))

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

def load_cves(filename: str):
    with open(filename, 'r', encoding='utf-8') as file:
        data = json.load(file)
    return data['CVE_Items']

#print(scan_ip('scanme.nmap.org'))
print(scan_ip('192.168.56.101'))

cve_data = load_cves('nvdcve-1.1-recent.json')
#print(cve_data)