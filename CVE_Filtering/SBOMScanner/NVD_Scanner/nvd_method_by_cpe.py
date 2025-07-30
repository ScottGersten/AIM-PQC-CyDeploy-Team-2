import paramiko
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading
import re

found_cve_ids = 0

COMMON_PREFIXES = ['lib', 'python-', 'perl-', 'golang-', 'nodejs-']

def strip_prefix(name):
    for prefix in COMMON_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name

def strip_trailing_version_suffix(name):
    return re.sub(r'\d+(off)?$', '', name)

def normalize_name(name):
    name = name.lower()
    name = name.replace('-', '')
    name = name.replace('_', '')
    name = strip_prefix(name)
    name = strip_trailing_version_suffix(name)
    return name

# def match_cves(installs, data):
#     global found_cve_ids

#     for item in data:
#         cve_id = item.get('id')
#         description = item.get('description', '')
#         raw = item.get('raw', {})

#         for pkg in installs:
#             name = pkg['name']
#             version = pkg['version']
#             if normalize_name(name) in normalize_name(description):
#                 pkg['cves'].append(cve_id)
#                 found_cve_ids += 1

def match_cves(installs, data):
    #matched_cves = []

    for pkg in installs:
        pkg_name = pkg['name'].lower()
        pkg_version = pkg['version']

        for item in data:
            cve_id = item['id']
            #nodes = item.get('configurations', {}).get('nodes', [])
            nodes = item['raw']['configurations'].get('nodes', [])

            for node in nodes:
                for cpe_match in node.get('cpe_match', []):
                    cpe23uri = cpe_match.get('cpe23uri', '')
                    vulnerable = cpe_match.get('vulnerable', False)

                    if not vulnerable:
                        continue
                        
                    parts = cpe23uri.split(':')
                    if len(parts) < 6:
                        continue

                    cpe_vendor = parts[3].lower()
                    cpe_product = parts[4].lower()
                    cpe_version = parts[5]

                    if pkg_name in (cpe_vendor, cpe_product):
                        #if pkg_version.startswith(cpe_version):
                        pkg['cves'].append(cve_id)

    #     if pkg['cves']:
    #         matched_cves.append(pkg)

    # return matched_cves

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
    start_time = time.time()

    with open('ip.txt', 'r') as f:
        ip = f.read()
    #output = get_installs(ip)

    with open ('installed.txt', 'r') as f:
        output = f.read()

    installs = parse_installs(output)

    with open('all_cves.json', 'r', encoding='utf-8') as file:
        all_cves = json.load(file)

    #print("SIZE: ",len(all_cves))
    # cve_id = all_cves[3]['id']
    # nodes = all_cves[3]['raw']['configurations'].get('nodes', [])
    # print(cve_id)
    # print(nodes)

    #matched = match_cves(installs, all_cves)
    match_cves(installs[0:100], all_cves)

    fails = successes = 0
    found_installs = []
    for pkg in installs:
        if not pkg['cves']:
            fails += 1
        else:
            successes += 1
            found_installs.append(pkg)
    print(f"Number of successful matches in run: {successes}")
    print(f"Number of failed matches in run: {fails}")

    with open('results.json', 'w', encoding='utf-8') as file, open('results_abridged.json', 'w', encoding='utf-8') as file_abr:
        json.dump(installs, file, indent=2)
        json.dump(found_installs, file_abr, indent=2)

    print(f"Number of found IDs: {found_cve_ids}")

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")

if __name__ == '__main__':
    main()