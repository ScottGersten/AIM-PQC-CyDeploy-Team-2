import json
import time
import re
import requests
from packaging.version import Version, InvalidVersion
from collections import defaultdict


# ------------------------- Load CVE Databases ------------------------- #

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

def load_ubuntu_cves(path='ubuntu_cves.json'):
    with open(path, 'r') as f:
        raw_entries = json.load(f)

    pkg_index = defaultdict(list)
    for entry in raw_entries:
        pkg_name = entry.get("Package")
        if not pkg_name:
            continue

        cve_id = entry.get("Candidate")
        description = entry.get("Description", "")
        patches = entry.get("Patches", {})

        for release, patch in patches.items():
            fixed_version = patch.get("fixed_version")
            status = patch.get("status")
            if status in ["released", "not-fixed", "needs-triage"]:
                pkg_index[pkg_name].append({
                    "id": cve_id,
                    "description": description,
                    "source": "ubuntu",
                    "release": release,
                    "fixed_version": fixed_version,
                    "status": status
                })

    return dict(pkg_index)


# ------------------------- Version Normalization ------------------------- #

def normalize_version(v):
    try:
        return Version(re.split(r'[-+~]', v)[0])
    except InvalidVersion:
        print(f"Invalid version: {v}")
        return None


# ------------------------- CVE Matching ------------------------- #

def get_ubuntu_cves(pkg_name, version, ubuntu_version="focal"):
    entries = ubuntu_cve_db.get(pkg_name, [])
    parsed_installed = normalize_version(version)
    relevant_cves = []

    for cve in entries:
        if cve.get('release') == ubuntu_version:
            fixed_version = cve.get('fixed_version')
            if fixed_version:
                parsed_fixed = normalize_version(fixed_version)
                if parsed_installed and parsed_fixed and parsed_installed < parsed_fixed:
                    relevant_cves.append(cve)
    return relevant_cves

def get_debian_cves(data, pkg_name, installed_version):
    if pkg_name not in data:
        return []

    pkg_data = data[pkg_name]
    cves = []
    parsed_installed = normalize_version(installed_version)

    for cve_id, cve_info in pkg_data.items():
        for release, release_data in cve_info.get('releases', {}).items():
            fixed_version = release_data.get('fixed_version')
            status = release_data.get('status')
            if fixed_version and status in ('open', 'resolved', 'not-fixed', 'vulnerable'):
                try:
                    parsed_fixed = normalize_version(fixed_version)
                    if parsed_installed and parsed_fixed and parsed_installed < parsed_fixed:
                        cves.append({
                            'id': cve_id,
                            'source': 'debian',
                            'release': release,
                            'fixed_version': fixed_version
                        })
                        break
                except Exception as e:
                    print(f"Version comparison error for {pkg_name}: {e}")
                    continue
    return cves

def get_nvd_cves(pkg_name, version):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {'apiKey': 'YOUR_API_KEY_HERE'}  # Replace with your API key
    params = {'keywordSearch': f"{pkg_name} {version}", 'resultsPerPage': 5}

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 429:
            time.sleep(30)
            return get_nvd_cves(pkg_name, version)
        response.raise_for_status()
        cve_items = response.json().get('vulnerabilities', [])
        return [{
            'id': item.get("cve", {}).get('id'),
            'description': item.get("cve", {}).get('descriptions', [{}])[0].get('value', 'No description'),
            'source': 'nvd'
        } for item in cve_items if 'cve' in item]
    except Exception as e:
        print(f"NVD query failed for {pkg_name}: {e}")
        return []


# ------------------------- Package Processing ------------------------- #

def parse_installs(text):
    packages = []
    for line in text.splitlines():
        if line.startswith('ii'):
            parts = line.split()
            packages.append({
                'name': parts[1],
                'version': parts[2],
                'description': ' '.join(parts[3:]),
                'cves': []
            })
    return packages

def scan_packages(packages):
    for pkg in packages:
        name = pkg['name']
        version = pkg['version']

        # Ubuntu detection
        if 'ubuntu' in version.lower():
            ubuntu_cves = get_ubuntu_cves(name, version)
            if ubuntu_cves:
                pkg['cves'] = ubuntu_cves
            else:
                pkg['cves'] = get_debian_cves(debian_data, name, version)
        else:
            pkg['cves'] = get_nvd_cves(name, version)


# ------------------------- Main ------------------------- #

def main():
    start = time.time()

    with open('installed.txt', 'r') as f:
        text = f.read()

    installs = parse_installs(text)

    global debian_data, ubuntu_cve_db
    debian_data = get_debian_tracker()
    ubuntu_cve_db = load_ubuntu_cves()

    scan_packages(installs)

    vulnerable = [pkg for pkg in installs if pkg['cves']]

    

    with open('results.json', 'w') as f:
        json.dump(vulnerable, f, indent=2)

    print(f"[DONE] Scanned {len(installs)} packages in {time.time() - start:.2f} seconds")
    print(f"[INFO] Found {len(vulnerable)} vulnerable packages. Results saved to results.json")

if __name__ == "__main__":
    main()
