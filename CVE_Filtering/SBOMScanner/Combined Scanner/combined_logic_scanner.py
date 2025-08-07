import json
import requests
from packaging import version as packaging_version
import paramiko
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor


def parse_installed_packages(file_path='installed.txt'):
    packages = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[1].lower()
                    full_version = parts[2].strip()
                    packages.append({
                        'name': name,
                        'version': full_version,
                        'cves': []
                    })
    return packages

def load_ubuntu_cves(json_path='ubuntu_cves.json'):
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_nvd_cves(json_path='all_cves.json'):
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# Looks at the service version if it is before or after the affected version. 

def normalize_affected(desc):
    patterns = [
        r'^(\S+)\s+-\s+([\w\d\.\-\:\+~]+)',
        r'(\b[\w\-\+\.]+)\s+(?:before|less than|<|<=|prior to)\s+([\w\d\.\-\:\+~]+)',
        r'(\b[\w\-\+\.]+)\s+(?:is\s+)?fixed in version\s+([\w\d\.\-\:\+~]+)'
    ]
    matches = []
    for pattern in patterns:
        matches += re.findall(pattern, desc, re.IGNORECASE | re.MULTILINE)
    return matches


def index_cves_by_package(cve_entries):
    index = defaultdict(list)
    for cve in cve_entries:
        desc_raw = cve.get('description', '')
        if isinstance(desc_raw, list):
            desc = ' '.join(d.get('value', '') for d in desc_raw if isinstance(d, dict))
        elif isinstance(desc_raw, str):
            desc = desc_raw
        else:
            desc = ''
        desc = desc.lower()
        
        for name, ver in normalize_affected(desc):
            index[name].append((ver, cve))
    return index

def match_ubuntu_cves(packages, ubuntu_index):
    def match(pkg):
        matched = []
        for version, cve in ubuntu_index.get(pkg['name'], []):
            try:
                if packaging_version.parse(pkg['version']) < packaging_version.parse(version):
                    matched.append({
                        'source': 'ubuntu',
                        'title': cve.get('title'),
                        'description': cve.get('description'),
                        
                    })
                
    
            except Exception:
                continue
        pkg['cves'] = matched
        return matched

    with ThreadPoolExecutor() as executor:
        list(executor.map(match, packages))


def index_nvd_by_keywords(cve_data):
    index = defaultdict(list)
    for entry in cve_data:
        desc = entry.get('description', '').lower()
        for word in re.findall(r'\b[a-z0-9\-\+\.]{3,}\b', desc):
            index[word].append(entry)
    return index

def match_nvd_cves(packages, nvd_index):
    def match(pkg):
        matched = []
        name = pkg['name']
        full_ver = pkg['version']
        aliases = set(re.findall(r'\b[a-z0-9\-\+\.]{3,}\b', name))

        related_entries = []
        for alias in aliases:
            related_entries.extend(nvd_index.get(alias, []))

        seen_ids = set()

        
            
        for entry in related_entries:
            

            cve_id = entry.get('id')
            desc = entry.get('description', '').lower()                      
            seen_ids.add(cve_id)

            if name in desc and ('version') in desc or full_ver in desc:
                if cve_id.startswith("TEMP"):
                    continue
                matched.append({
                    'source': 'nvd',
                    'cve_id': cve_id,

                    'description': desc
                })

        if 'cves' not in pkg:
            pkg['cves'] = []

        pkg['cves'].extend(matched)


    with ThreadPoolExecutor() as executor:
        list(executor.map(match, packages))


debian_fails = 0
debian_successes = 0

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

def get_debian_cves(data, pkg_name, installed_version):
    global debian_fails, debian_successes

    if pkg_name not in data:
        debian_fails += 1
        return []

    debian_successes += 1
    pkg_data = data[pkg_name]
    seen = set()
    return get_debian_cves_for_package(pkg_data, installed_version, seen)

def get_debian_cves_for_package(pkg_data, installed_version, seen):
    cves = []
    installed_major = installed_version.split('.')[0:2]  
    installed_major_str = ".".join(installed_major)

    for cve_id, cve_info in pkg_data.items():
        if cve_id.startswith("TEMP"):
            continue

        description = cve_info.get('description', '').lower()

        if installed_major_str not in description:
            continue  

        for release, release_data in cve_info.get('releases', {}).items():
            fixed_version = release_data.get('fixed_version')
            status = release_data.get('status')

            if not fixed_version or not installed_version:
                continue

            if status in ('open', 'resolved', 'not-fixed', 'vulnerable'):
                try:
                    if packaging_version.parse(installed_version) < packaging_version.parse(fixed_version):
                        if cve_id not in seen:
                            cves.append({
                                'source': 'debian',
                                'cve_id': cve_id,
                                'description': cve_info.get('description', ''),
                                'release': release,
                            })
                            seen.add(cve_id)
                except Exception:
                    continue

    return cves



def main():
    start = time.time()

    #with open('ip.txt', 'r') as f:
     #   ip = f.read().strip()

   # print(f"[+] Fetching installed packages from {ip}...")
   # get_installs(ip)

    print("Scanning installed.txt...")
    print("Parsing installed packages...")
    packages = parse_installed_packages()
    print(f"{len(packages)} packages found.")

    ubuntu_pkgs = [pkg for pkg in packages if "ubuntu" in pkg['version'].lower()]
    non_ubuntu_pkgs = [pkg for pkg in packages if "ubuntu" not in pkg['version'].lower()]

    if ubuntu_pkgs:
        print("Ubuntu detected. Scanning Ubuntu CVE Database.")
        ubuntu_cves_raw = load_ubuntu_cves()
        ubuntu_index = index_cves_by_package(ubuntu_cves_raw)
        match_ubuntu_cves(ubuntu_pkgs, ubuntu_index)


    if non_ubuntu_pkgs:
        print("Trying Debian Security Tracker for non-Ubuntu packages...")
        debian_data = get_debian_tracker()
        for pkg in non_ubuntu_pkgs:
            pkg['cves'] = get_debian_cves(debian_data, pkg['name'], pkg['version'])

            

    fallback_to_nvd_non_ubuntu = [p for p in non_ubuntu_pkgs if not p['cves']]
    if fallback_to_nvd_non_ubuntu:
        print("Fallback: scanning NVD for non-Ubuntu packages with no Debian matches...")
        nvd_cves = load_nvd_cves()
        nvd_index = index_nvd_by_keywords(nvd_cves)
        match_nvd_cves(fallback_to_nvd_non_ubuntu, nvd_index)

    fallback_to_nvd_ubuntu = [p for p in ubuntu_pkgs if not p['cves']]
    if fallback_to_nvd_ubuntu:
        print("Fallback: scanning NVD for Ubuntu packages with no matches...")
        match_nvd_cves(fallback_to_nvd_ubuntu, nvd_index)

    vulnerable = [pkg for pkg in packages if pkg['cves']]
   

    print("\nSummary:")
    total_successes = len(vulnerable)
    total_fails = len(packages) - total_successes
    print(f"Total successful matches: {total_successes}")
    print(f"Total failed matches: {total_fails}")
    print(f"Ubuntu matches: {sum(1 for p in ubuntu_pkgs if p['cves'])}")
    print(f"Debian matches: {debian_successes}")
    print(f"NVD matches: {sum(1 for p in packages if any(c.get('source') == 'nvd' for c in p['cves']))}")

    with open('combined_results.json', 'w') as f:
        json.dump(vulnerable, f, indent=2)

    print("\nScan complete. CVEs saved to combined_results.json")
    print(f"Took {time.time() - start:.2f} seconds.")

if __name__ == '__main__':
    main()
