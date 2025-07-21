import paramiko
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading

def match_cves(installs, data, outer_threads=100, inner_threads=50):
    installs_lock = {pkg['name']: threading.Lock() for pkg in installs}

    def check_data(item):
        cve_id = item.get('id')
        description = item.get('description', '')

        def check_pkg(pkg):
            name = pkg['name']
            if name.lower() in description.lower():
                with installs_lock['name']:
                    pkg['cves'].append(cve_id)
        
        with ThreadPoolExecutor(max_workers=inner_threads) as inner_executor:
            inner_futures = [inner_executor.submit(check_pkg, pkg) for pkg in installs]
            for f in as_completed(inner_futures):
                pass
        
    with ThreadPoolExecutor(max_workers=outer_threads) as outer_executor:
        outer_futures = [outer_executor.submit(check_data, item) for item in data]
        for f in as_completed(outer_futures):
            pass


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