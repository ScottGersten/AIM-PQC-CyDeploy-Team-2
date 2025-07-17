import paramiko
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

def get_debian_cves(data, pkg):

    if pkg not in data:
        return None
    
    pkg_data = data[pkg]
    cves = []
    for cve in pkg_data.items():
        cves.append(cve[0])
    
    return cves

def debian_method(installs):
    # Debian Tracker Method
    debian_fails = debian_successes = 0

    data = get_debian_tracker()

    for pkg in installs:
        cves = get_debian_cves(data, pkg['name'])
        if cves is not None:
            pkg['cves'].append(cves)

    # for pkg in installs[30:40]:
    #     cves = get_cves(data, pkg['name'])
    #     pkg['cves'] = cves
    #     print(cves)

    # print(installs[30:40])

    # with open('results.json', 'w', encoding='utf-8') as file:
    #     json.dump(installs, file, indent=2)

    # for pkg in installs:
    #     if not pkg['cves']:
    #         debian_fails += 1
    #     else:
    #         debian_successes += 1

    # print(f"Number of successful matches in Debian: {debian_successes}")
    # print(f"Number of failed matches in Debian: {debian_fails}")

def osv_threading(pkgs, max_threads=100):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(get_osv_cves, pkg['name']): pkg for pkg in pkgs}
        for future in as_completed(futures):
            pkg = futures[future]
            cves = future.result()
            if cves is not None:
                pkg['cves'].append(cves)

def get_osv_cves(pkg, ecosystem='Debian'):

    url = 'https://api.osv.dev/v1/query'
    payload = {
        'package':{
            'name': pkg,
            'ecosystem': ecosystem
        }
    }

    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        results = response.json()

        vulns = results.get('vulns', [])
        cves = []
        for vuln in vulns:
            if 'aliases' in vuln:
                cves.extend(vuln['aliases'])
            else:
                cves.append(vuln.get('id'))
        #return list(set(cves))
        if cves:
            #osv_successes += 1
            return list(set(cves))
        else:
            #osv_fails += 1
            return None
    
    except Exception as e:
        #osv_fails += 1
        print(f"{e}")
        return None

def osv_method(installs):
    osv_fails =  osv_successes = 0

    # OSV JSON Method
    osv_threading(installs)

    # for pkg in installs[30:40]:
    #     cves = get_osv(pkg['name'])
    #     pkg['cves'] = cves

    # with open('results.json', 'w', encoding='utf-8') as file:
    #     json.dump(installs, file, indent=2)

    # for pkg in installs:
    #     if not pkg['cves']:
    #         osv_fails += 1
    #     else:
    #         osv_successes += 1

    # print(f"Number of successful matches in OSV: {osv_successes}")
    # print(f"Number of failed matches in OSV: {osv_fails}")

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
                #'description': ''.join(splits[3:]),
                'cves': []
            })
    return packages

def main():
    with open('ip.txt', 'r') as f:
        ip = f.read()
    #ip = '192.168.56.101'
    #output = get_installs(ip)
    with open ('installed.txt', 'r') as f:
        output = f.read()
    installs = parse_installs(output)

    debian_method(installs)

    osv_method(installs)

    full_fails = full_successes = 0

    for pkg in installs:
        if not pkg['cves']:
            full_fails += 1
        else:
            full_successes += 1

    print(f"Number of successful matches in Full Run: {full_successes}")
    print(f"Number of failed matches in Full Run: {full_fails}")

    with open('results.json', 'w', encoding='utf-8') as file:
        json.dump(installs, file, indent=2)

if __name__ == '__main__':
    main()

