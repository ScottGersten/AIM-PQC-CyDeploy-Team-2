import paramiko
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading

# def match_cves(installs, data, max_threads=300):
#     matched_cves = []
#     matches_lock = threading.Lock()
#     installs_lock = {pkg['name']: threading.Lock() for pkg in installs}

#     with ThreadPoolExecutor(max_workers=max_threads) as executor:
#         futures = [executor.submit(process_item, item, installs, installs_lock) for item in data]
#         for future in as_completed(futures):
#             matches = future.result()
#             if matches:
#                 with matches_lock:
#                     matched_cves.append(matches)

#     return matched_cves

# def process_item(item, installs, lock):
#     matches = []
#     cve_id = item.get('id')
#     description = item.get('description', '')

#     for pkg in installs:
#         name = pkg['name']
#         version = pkg['version']
#         if name.lower() in description.lower():
#             matches.append((cve_id, name, version, description))
#             with lock[name]:
#                 pkg['cves'].append(cve_id)
    
#     return matches

# def match_cves(installs, data, max_threads=150):
#     lock = threading.Lock()

#     def process_item(item):
#         cve_id = item.get('id')
#         description = item.get('description', '')
        
#         for pkg in installs:
#             name = pkg['name']
#             if name.lower() in description.lower():
#                 with lock:
#                     pkg['cves'].append(cve_id)
    
#     with ThreadPoolExecutor(max_workers=max_threads) as executor:
#         futures = {executor.submit(process_item, item): item for item in data}
#         for future in as_completed(futures):
#             try:
#                 future.result()
#             except Exception as e:
#                 print(f"Error processing CVE: {e}")

def match_cves(installs, data, max_threads=250):
    installs_map = {pkg['name'].lower(): pkg for pkg in installs}
    lock = threading.Lock()

    def process_item(item):
        cve_id = item.get('id')
        description = item.get('description', '').lower()

        for name in installs_map:
            if name in description:
                with lock:
                    installs_map[name]['cves'].append(cve_id)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(process_item, data)

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
    #installs = installs[340:440]

    with open('all_cves.json', 'r', encoding='utf-8') as file:
        all_cves = json.load(file)

    match_cves(installs, all_cves)
    # matched_cves = match_cves(installs, all_cves)
    # with open('matched.json', 'w', encoding='utf-8') as file:
    #     json.dump(matched_cves, file, indent=2)

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

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")

if __name__ == '__main__':
    main()