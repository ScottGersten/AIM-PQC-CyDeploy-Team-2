import paramiko
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

debian_fails = 0
debian_successes = 0

osv_fails = 0
osv_successes = 0

vulners_fails = 0
vulners_successes = 0

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

def get_debian_cves(data, pkg):
    global debian_fails, debian_successes

    if pkg not in data:
        debian_fails += 1
        return None
    
    debian_successes += 1
    pkg_data = data[pkg]
    cves = []
    for cve in pkg_data.items():
        cves.append(cve[0])
    
    return cves

def debian_method(installs):
    # Debian Tracker Method
    data = get_debian_tracker()

    for pkg in installs:
        cves = get_debian_cves(data, pkg['name'])
        pkg['cves'] = cves

    # for pkg in installs[30:40]:
    #     cves = get_cves(data, pkg['name'])
    #     pkg['cves'] = cves
    #     print(cves)

    # print(installs[30:40])

    with open('results.json', 'w', encoding='utf-8') as file:
        json.dump(installs, file, indent=2)

    print(f"Number of successful matches in Debian: {debian_successes}")
    print(f"Number of failed matches in Debian: {debian_fails}")

def osv_threading(pkgs, max_threads=100):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(get_osv_cves, pkg['name']): pkg for pkg in pkgs}
        for future in as_completed(futures):
            pkg = futures[future]
            cves = future.result()
            pkg['cves'] = cves

def get_osv_cves(pkg, ecosystem='Debian'):
    global osv_fails, osv_successes

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
    global osv_fails, osv_successes

    # OSV JSON Method
    osv_threading(installs)

    # for pkg in installs[30:40]:
    #     cves = get_osv(pkg['name'])
    #     pkg['cves'] = cves

    with open('results.json', 'w', encoding='utf-8') as file:
        json.dump(installs, file, indent=2)

    for pkg in installs:
        if pkg['cves'] == None:
            osv_fails += 1
        else:
            osv_successes += 1

    print(f"Number of successful matches in OSV: {osv_successes}")
    print(f"Number of failed matches in OSV: {osv_fails}")

def vulners_threading(pkgs, api_key, max_threads=100):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(get_vulners_cves, pkg['name'], pkg['version'], api_key): pkg for pkg in pkgs}
        for future in as_completed(futures):
            pkg = futures[future]
            cves = future.result()
            pkg['cves'] = cves

def get_vulners_cves(pkg, version, api_key):
    #url = 'https://vulners.com/api/v3/burp/software/'
    url = 'https://vulners.com/api/v3/search/lucene/'
    headers = {'Content-Type': 'application/json'}
    query = f"{pkg} {version}"
    payload = {
        'query': query,
        'apiKey': api_key
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        result = response.json()

        cves = []
        for item in result['data']['search']:
            source = item.get('_source', {})
            cvelist = source.get('cvelist', [])
            cves.extend(cvelist)
        cves = sorted(list(set(cves)))
        return cves

    except Exception as e:
        print(f"{e}")
        return None

def vulners_method(installs):
    global vulners_successes, vulners_fails

    with open('vulners_api_key.txt', 'r') as file:
        api_key = file.read()

    vulners_threading(installs, api_key)

    with open('results.json', 'w', encoding='utf-8') as file:
        json.dump(installs, file, indent=2)

    for pkg in installs:
        if pkg['cves'] == None:
            vulners_fails += 1
        else:
            vulners_successes += 1

    print(f"Number of successful matches in Vulners: {vulners_successes}")
    print(f"Number of failed matches in Vulners: {vulners_fails}")
    

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

def main():
    with open('ip.txt', 'r') as f:
        ip = f.read()
    #output = get_installs(ip)
    with open ('installed.txt', 'r') as f:
        output = f.read()
    installs = parse_installs(output)

    debian_method(installs)

    #osv_method(installs)

    #vulners_method(installs)

if __name__ == '__main__':
    main()

