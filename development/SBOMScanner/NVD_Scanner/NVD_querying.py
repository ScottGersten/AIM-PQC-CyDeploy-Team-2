import requests
import json
import time
import time
import paramiko
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

API_KEY = "9e5c128e-61df-45eb-86de-f64db224476a"  
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
lock = Lock()
start_t = time.time()

# Simplifies the version string by removing distribution-specific suffixes
def simplify_version(version):
    return re.split(r'[-+~]', version)[0]

def get_cpe(pkg_name, pkg_version):
    headers = {"apiKey": API_KEY}
    params = {"keywordSearch": pkg_name, "resultsPerPage": 50} # Searches the databases based on the package name.

    try:
        with lock:
            time.sleep(1.2)  # NVD rate-limiting so it doesn't overflow with query requests.

        response = requests.get(CPE_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        filtered_cpes = []
        simplified = simplify_version(pkg_version)

 # Extracts and filters the CPEs that match the given simplified version
        for item in data.get("products", []):
            cpe_name = item['cpe']['cpeName']
            parts = cpe_name.split(":")
            if len(parts) > 5:
                cpe_version = parts[5]
                if simplified.startswith(cpe_version):
                    filtered_cpes.append(cpe_name)

        return filtered_cpes if filtered_cpes else None

    except requests.exceptions.RequestException as e:
        print(f"[CPE] Error for {pkg_name}: {e}")
        return None

# Implements threading for effiency.
def cpe_threading(pkgs, max_threads=10):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(get_cpe, pkg['name'], pkg['version']): pkg for pkg in pkgs}
        for future in as_completed(futures):
            pkg = futures[future]
            try:
                cpes = future.result()
                pkg['cpes'] = cpes if cpes else []
            except Exception as e:
                print(f"[Thread Error] {pkg['name']}: {e}")
                pkg['cpes'] = []

# Based on the discovered CPE name, it collerates the relevant CVEs.
def get_cves_for_cpe(cpe_name):
    headers = {"apiKey": API_KEY}
    params = {"cpeName": cpe_name, "resultsPerPage": 100}

    try:
        time.sleep(1.2)
        response = requests.get(CVE_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        cve_list = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            if "id" in cve:
                cve_list.append({
                    "id": cve["id"],
                    "description": cve.get("descriptions", [{}])[0].get("value", ""),
                    "cvss": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
                })
        return cve_list

    except Exception as e:
        print(f"[CVE Fetch] Error for CPE {cpe_name}: {e}")
        return []
    

# Connects via SSH to retrieve installed packages
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
                'cpes': [],
                'cves': []
            })
    return packages

def main():
    with open('installed.txt', 'r') as f:
        output = f.read()

    installs = parse_installs(output)
    print(f"Parsed {len(installs)} installed packages.")

    print("Starting CPE queries with threading...")
    cpe_threading(installs)
    print("Done with CPE queries.")

    print("Fetching CVEs for discovered CPEs...")
    for pkg in installs:
        for cpe in pkg.get('cpes', []):
            pkg['cves'] += get_cves_for_cpe(cpe)

    total_fails = total_successes = 0
    found_installs = []

   

    # Save full results
    with open('cpe_results.json', 'w') as file:
        json.dump(installs, file, indent=2)

        
    for pkg in found_installs:
        print(f"\n{pkg['name']} ({pkg['version']})")
        for cve in pkg['cves']:
            print(f"  - {cve['id']} | CVSS: {cve['cvss']}\n    {cve['description']}")

    for pkg in installs:
            if not pkg['cves']:
                total_fails += 1
            else:
                total_successes += 1
                found_installs.append(pkg)

    # Save only packages with CVEs
    with open('matched_cves.json', 'w') as file:
        json.dump(found_installs, file, indent=2)

    

    print(f"Successful CVE matches: {total_successes}")
    print(f"No CVEs found for: {total_fails} packages")

end_t = time.time()
total_time = end_t - start_t

if __name__ == "__main__":
    main()
    print (total_time)

