import paramiko
import requests
import json

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

def get_cves(data, pkg):
    if pkg not in data:
        return None
    
    pkg_data = data[pkg]
    cves = []
    for cve in pkg_data.items():
        cves.append(cve[0])
    
    return cves

def get_installs(ip, username='msfadmin', password='msfadmin'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(ip, username=username, password=password)

    stdin, stdout, stderr = ssh.exec_command('dpkg -l')
    output = stdout.read().decode('utf-8')

    ssh.close()

    with open('installed.txt', 'w', encoding='utf-8') as file:
        file.write(output)

    return output

def parse_installs(installs):
    packages = []
    for line in installs.splitlines():
        if line.startswith('ii'):
            splits = line.split()
            packages.append({
                'name': splits[1],
                'version': splits[2],
                'description': ''.join(splits[3:]),
                'cves': None
            })
    return packages

ip = '192.168.56.101'
output = get_installs(ip)
installs = parse_installs(output)
data = get_debian_tracker()

for pkg in installs[30:40]:
    cves = get_cves(data, pkg['name'])
    pkg['cves'] = cves
    print(cves)

print(installs[30:40])

