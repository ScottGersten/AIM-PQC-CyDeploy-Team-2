import json
import re
import time
from packaging import version
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

def simplify_version(version_str):
    return re.split(r'[-+~]', version_str)[0]

def parse_installed_packages(file_path='installed.txt'):
    packages = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[1].lower()
                    full_version = parts[2].strip()
                    base_version = simplify_version(full_version)
                    packages.append({
                        'name': name,
                        'version': full_version,
                        'base_version': base_version,
                        'cves': []
                    })
    return packages

def load_ubuntu_cves(json_path='ubuntu_cves.json'):
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def normalize_affected(desc):
    patterns = [
        r'^(\S+)\s+-\s+([\w\d\.\-\:\+~]+)',
        r'(\b[\w\-\+\.]+)\s+(?:before|less than|<|<=|prior to)\s+([\w\d\.\-\:\+~]+)',
        r'(\b[\w\-\+\.]+)\s+(?:is\s+)?fixed in version\s+([\w\d\.\-\:\+~]+)'
    ]
    matches = []
    for pattern in patterns:
        matches += re.findall(pattern, desc, re.IGNORECASE | re.MULTILINE)
    return [(pkg.lower(), simplify_version(ver)) for pkg, ver in matches]

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
import re  # Move this to the top of your script

def match_package(pkg, cve_index):
    pkg_name = pkg['name']
    base_version = pkg['base_version']
    matched = []

    # Get all matching aliases
    candidates = cve_index.get(pkg_name, [])

    for affected_version, cve in candidates:
        try:
            if version.parse(base_version) < version.parse(affected_version):

                matched.append({
                    'cve_id': cve.get('CVE'),
                    'affected_pkg': pkg_name,
                    'affected_version': affected_version,
                    'title': cve.get('title', ''),
                    'description': cve.get('description', ''),
                    'severity': cve.get('priority', 'unknown')
                })

        except Exception:
            continue

    pkg['cves'] = matched
    return matched


def match_cves_fast(packages, cve_entries):
    cve_index = index_cves_by_package(cve_entries)
    matched = []

    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda pkg: match_package(pkg, cve_index), packages))

    for m in results:
        matched.extend(m)
    return matched

def main():
    start = time.time()

    print("Parsing installed packages...")
    packages = parse_installed_packages()
    print(f"{len(packages)} packages found.")

    print("Loading Ubuntu CVEs...")
    cve_data = load_ubuntu_cves()
    print(f"{len(cve_data)} CVEs loaded.")

    print("Matching CVEs to installed packages...")
    matches = match_cves_fast(packages, cve_data)
    print(f"Found {len(matches)} CVE matches.")

    vuln_pkgs = [p for p in packages if p['cves']]
    print(f"{len(vuln_pkgs)} vulnerable packages with {sum(len(p['cves']) for p in vuln_pkgs)} total CVEs.")
    print(f"{len(packages) - len(vuln_pkgs)} packages with no known vulnerabilities.")

    fails = successes = 0
    found_installs = []
    for pkg in packages:
        if not pkg['cves']:
            fails += 1
        else:
            successes += 1
            found_installs.append(pkg)
    print(f"Number of successful matches in run: {successes}")
    print(f"Number of failed matches in run: {fails}")
    # Save results
    with open('matched_ubuntu_packages.json', 'w') as f:
        json.dump(vuln_pkgs, f, indent=2)

    with open('all_packages_cves.json', 'w') as f:
        json.dump(packages, f, indent=2)

    print(f"Done in {time.time() - start:.2f} seconds.")

if __name__ == '__main__':
    main()
