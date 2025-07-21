import paramiko
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading

thread_lock = threading.Lock()

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
    
    return sorted(cves)

def debian_method(installs):
    data = get_debian_tracker()

    for pkg in installs:
        cves = get_debian_cves(data, pkg['name'])
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
            #cves.append(vuln.get('id'))
        if cves:
            return sorted(list(set(cves)))
        else:
            return None
    
    except Exception as e:
        print(f"{e}")
        return None
    
def osv_method(pkgs, max_threads=100):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(get_osv_cves, pkg['name']): pkg for pkg in pkgs}
        for future in as_completed(futures):
            pkg = futures[future]
            cves = future.result()
            if cves is not None:
                with thread_lock:
                    pkg['cves'].append(cves)

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

def vulners_method(pkgs, max_threads=100):
    with open('vulners_api_key.txt', 'r') as file:
        api_key = file.read()
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(get_vulners_cves, pkg['name'], pkg['version'], api_key): pkg for pkg in pkgs}
        for future in as_completed(futures):
            pkg = futures[future]
            cves = future.result()
            if cves is not None:
                with thread_lock:
                    pkg['cves'].append(cves)

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

def flatten_results(installs):
    for pkg in installs:
        flattened_results = [item for sublist in pkg['cves'] for item in sublist]
        flattened_results = sorted(list(flattened_results))
        pkg['cves'] = flattened_results

def main():
    start_time = time.time()

    with open('ip.txt', 'r') as f:
        ip = f.read()
    #ip = '192.168.56.101'
    #output = get_installs(ip)

    with open ('installed.txt', 'r') as f:
        output = f.read()

    installs = parse_installs(output)

    debian_method(installs)

    osv_method(installs)

    #vulners_method(installs)

    flatten_results(installs)

    full_fails = full_successes = 0
    found_installs = []

    for pkg in installs:
        if not pkg['cves']:
            full_fails += 1
        else:
            full_successes += 1
            found_installs.append(pkg)

    print(f"Number of successful matches in Full Run: {full_successes}")
    print(f"Number of failed matches in Full Run: {full_fails}")

    with open('results.json', 'w', encoding='utf-8') as file:
        json.dump(installs, file, indent=2)

    with open('results_abridged.json', 'w', encoding='utf-8') as file:
        json.dump(found_installs, file, indent=2)
    
    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")

if __name__ == '__main__':
    main()

