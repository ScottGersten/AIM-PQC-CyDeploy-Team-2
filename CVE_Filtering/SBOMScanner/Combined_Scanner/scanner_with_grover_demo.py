import os
import json
import re
import time
import math
import requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from packaging import version as packaging_version


QISKIT_AVAILABLE = False
AER_AVAILABLE = False

try:
    from qiskit import QuantumCircuit, transpile
    QISKIT_AVAILABLE = True
except Exception:
    QISKIT_AVAILABLE = False

try:
    from qiskit_aer import AerSimulator
    AER_AVAILABLE = True
except Exception:
    try:
        from qiskit import Aer
        AER_AVAILABLE = True
    except Exception:
        AER_AVAILABLE = False

INSTALLED_FILE = "installed.txt"
UBUNTU_CVES_JSON = "ubuntu_cves.json"
NVD_JSON = "all_cves.json"
OUTPUT_JSON = "combined_results.json"
DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"


def parse_installed_packages(file_path=INSTALLED_FILE):
    packages = []
    if not os.path.exists(file_path):
        print(f"[!] Installed packages file not found: {file_path}")
        return packages
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[1].lower()
                    full_version = parts[2].strip()
                    packages.append({'name': name, 'version': full_version, 'cves': []})
    return packages


def load_json_file(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading {path}: {e}")
        return None

def load_json_url(url, timeout=15):
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[!] Failed to load JSON from URL {url}: {e}")
        return None


def index_ubuntu_cves_from_file(path=UBUNTU_CVES_JSON):
    if path.startswith("http://") or path.startswith("https://"):
        data = load_json_url(path)
    else:
        data = load_json_file(path)
    index = defaultdict(list)
    if not data:
        return index
    for entry in data:
        pkg_name = entry.get('package_name') or entry.get('name')
        if not pkg_name:
            continue
        pkg_name = pkg_name.lower()
        index[pkg_name].append({
            'cve_id': entry.get('cve_id'),
            'description': entry.get('description', ''),
            'fixed_version': entry.get('fixed_version'),
            'release': entry.get('release')
        })
    return index

def match_ubuntu_cves(packages, ubuntu_index):
    for pkg in packages:
        name = pkg['name']
        if name in ubuntu_index:
            for entry in ubuntu_index[name]:
                try:
                    if entry.get('fixed_version') and packaging_version.parse(pkg['version']) < packaging_version.parse(entry['fixed_version']):
                        pkg['cves'].append({
                            'source': 'ubuntu',
                            'cve_id': entry.get('cve_id'),
                            'description': entry.get('description', ''),
                            'release': entry.get('release'),
                            'fixed_version': entry.get('fixed_version')
                        })
                except Exception:
                    pkg['cves'].append({
                        'source': 'ubuntu',
                        'cve_id': entry.get('cve_id'),
                        'description': entry.get('description', ''),
                        'release': entry.get('release'),
                        'fixed_version': entry.get('fixed_version')
                    })


def get_debian_tracker(timeout=20):
    try:
        r = requests.get(DEBIAN_TRACKER_URL, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[!] Could not fetch Debian tracker: {e}")
        return {}

def get_debian_cves_for_package(pkg_data, installed_version):
    cves = []
    seen = set()
    if not installed_version:
        return cves
    for cve_id, cve_info in pkg_data.items():
        if cve_id.startswith("TEMP"):
            continue
        for release, release_data in cve_info.get('releases', {}).items():
            fixed_version = release_data.get('fixed_version')
            status = release_data.get('status')
            if not fixed_version:
                continue
            if status not in ('open', 'resolved', 'not-fixed', 'vulnerable'):
                continue
            try:
                if packaging_version.parse(installed_version) < packaging_version.parse(fixed_version):
                    if cve_id not in seen:
                        cves.append({
                            'source': 'debian',
                            'cve_id': cve_id,
                            'description': cve_info.get('description', ''),
                            'release': release,
                            'fixed_version': fixed_version
                        })
                        seen.add(cve_id)
            except Exception:
                continue
    return cves


def index_nvd_by_keywords(cve_data):
    index = defaultdict(list)
    if not cve_data:
        return index
    items = []
    if isinstance(cve_data, dict):
        if 'CVE_Items' in cve_data:
            items = cve_data['CVE_Items']
        elif 'vulnerabilities' in cve_data:
            items = cve_data['vulnerabilities']
        else:
            items = cve_data.get('items', [])
    elif isinstance(cve_data, list):
        items = cve_data
    for entry in items:
        desc = ""
        cid = None
        if isinstance(entry, dict):
            if 'cve' in entry and isinstance(entry['cve'], dict):
                cid = entry['cve'].get('CVE_data_meta', {}).get('ID') or entry.get('id')
                desc_parts = entry['cve'].get('description', {}).get('description_data', [])
                if isinstance(desc_parts, list):
                    desc = " ".join(d.get('value', '') for d in desc_parts if isinstance(d, dict))
                else:
                    desc = str(entry.get('cve', {}).get('description', ''))
            else:
                cid = entry.get('id') or entry.get('cve')
                desc = str(entry.get('description', ''))
        desc = (desc or "").lower()
        for word in re.findall(r'\b[a-z0-9\-\+\.]{3,}\b', desc):
            index[word].append({'id': cid, 'description': desc, 'raw': entry})
    return index

def match_nvd_cves(packages, nvd_index_or_list):
    is_index = isinstance(nvd_index_or_list, dict)
    cve_list = None
    if not is_index:
        cve_list = nvd_index_or_list
    def match(pkg):
        matched = []
        name = pkg['name'].lower()
        full_ver = pkg['version']
        try:
            parsed_installed = packaging_version.parse(full_ver)
        except Exception:
            parsed_installed = None
        candidates = []
        if is_index:
            aliases = set(re.findall(r'\b[a-z0-9\-\+\.]{3,}\b', name))
            for alias in aliases:
                candidates.extend(nvd_index_or_list.get(alias, []))
        else:
            candidates = cve_list or []
        seen = set()
        for entry in candidates:
            if isinstance(entry, dict) and 'raw' in entry:
                cve_id = entry.get('id')
                desc = entry.get('description', '')
            elif isinstance(entry, dict):
                cve_id = entry.get('id') or entry.get('cve')
                desc = str(entry.get('description', ''))
            else:
                continue
            if not cve_id or cve_id in seen:
                continue
            if name not in desc:
                continue
            matched_cve = False
            before_match = re.search(rf"{re.escape(name)}.*before\s+(\d+(?:\.\d+)+)", desc)
            if before_match and parsed_installed:
                try:
                    if parsed_installed < packaging_version.parse(before_match.group(1)):
                        matched_cve = True
                except Exception:
                    pass
            if matched_cve:
                seen.add(cve_id)
                matched.append({
                    'source': 'nvd',
                    'cve_id': cve_id,
                    'description': desc
                })
        pkg['cves'].extend(matched)
    with ThreadPoolExecutor() as executor:
        list(executor.map(match, packages))


def grover_oracle_for_index(num_qubits, target_index):
    qc = QuantumCircuit(num_qubits)
    target_bits = format(target_index, f'0{num_qubits}b')[::-1]
    zero_inds = [i for i, b in enumerate(target_bits) if b == '0']
    if zero_inds:
        qc.x(zero_inds)
    if num_qubits > 1:
        qc.h(num_qubits - 1)
        qc.mcx(list(range(num_qubits - 1)), num_qubits - 1)
        qc.h(num_qubits - 1)
    else:
        qc.z(0)
    if zero_inds:
        qc.x(zero_inds)
    return qc

def grover_diffuser(num_qubits):
    qc = QuantumCircuit(num_qubits)
    qc.h(range(num_qubits))
    qc.x(range(num_qubits))
    if num_qubits > 1:
        qc.h(num_qubits - 1)
        qc.mcx(list(range(num_qubits - 1)), num_qubits - 1)
        qc.h(num_qubits - 1)
    else:
        qc.z(0)
    qc.x(range(num_qubits))
    qc.h(range(num_qubits))
    return qc

def grover_search_simulator(num_items, target_index, shots=1024):
    if not QISKIT_AVAILABLE or not AER_AVAILABLE or num_items == 0:
        return None, {}
    num_qubits = 0
    while 2 ** num_qubits < num_items:
        num_qubits += 1
    if num_qubits == 0:
        return 0, {'0': shots}

    r = max(1, int(math.floor(math.pi / (4 * math.asin(math.sqrt(1 / (2 ** num_qubits)))))))
    qc = QuantumCircuit(num_qubits, num_qubits)
    qc.h(range(num_qubits))

    oracle = grover_oracle_for_index(num_qubits, target_index)
    diffuser = grover_diffuser(num_qubits)

    for _ in range(r):
        qc = qc.compose(oracle)
        qc = qc.compose(diffuser)

    qc.measure_all()

    try:
        simulator = AerSimulator()
        t_qc = transpile(qc, simulator)
        job = simulator.run(t_qc, shots=shots)
        result = job.result()
        counts = result.get_counts()
        found_state = max(counts, key=counts.get)
        found_index = int(found_state.replace(" ", ""), 2)        
        return found_index, counts
    except Exception as e:
        print(f"Grover simulation failed: {e}")
    return target_index, {format(target_index, f'0{num_qubits}b'): shots}


def main():
    start = time.time()

   
    packages = parse_installed_packages()


    ubuntu_pkgs = [p for p in packages if 'ubuntu' in (p['version'] or '').lower()]
    ubuntu_index = index_ubuntu_cves_from_file(UBUNTU_CVES_JSON)
    match_ubuntu_cves(ubuntu_pkgs, ubuntu_index)

    
    non_ubuntu_pkgs = [p for p in packages if p not in ubuntu_pkgs]
    debian_data = {}
    if non_ubuntu_pkgs:
        debian_data = get_debian_tracker()
        for pkg in non_ubuntu_pkgs:
            pkg_name = pkg['name']
            if pkg_name in debian_data:
                pkg['cves'] = get_debian_cves_for_package(
                    debian_data[pkg_name], pkg['version']
                )

  
    nvd_raw = load_json_file(NVD_JSON)
    nvd_index = index_nvd_by_keywords(nvd_raw) if nvd_raw else {}
    if nvd_raw:
        match_nvd_cves(packages, nvd_index)

    
    ubuntu_matches = sum(1 for p in ubuntu_pkgs if p.get('cves'))
    debian_matches = sum(1 for p in non_ubuntu_pkgs if p.get('cves'))
    nvd_matches = sum(1 for p in packages if p.get('cves') and any(
        cve.get('source') == 'nvd' for cve in p.get('cves', [])
    ))

    vulnerable = [p for p in packages if p.get('cves')]

  
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(vulnerable, f, indent=2)

    
    print(f"Total packages: {len(packages)}")
    print(f"Ubuntu CVE matches: {ubuntu_matches}")
    print(f"Debian CVE matches: {debian_matches}")
    print(f"NVD CVE matches: {nvd_matches}")
    print(f"Total unique vulnerable packages: {len(vulnerable)}") # Packages with more than one CVE match.
    total = ubuntu_matches + debian_matches + nvd_matches

  
    if vulnerable and QISKIT_AVAILABLE and AER_AVAILABLE:
        demo_n = min(8, len(vulnerable)) # Grover runs on the first 8 vulerable packages (doesn't do it based off of the severity of the package yet).
        demo_candidates = vulnerable[:demo_n]
        print(f"\n[Grover Demo] Running local Grover simulator on {demo_n} candidates...")
        found_idx, counts = grover_search_simulator(demo_n, 0, shots=1024)
        if found_idx is not None:
            print(f"[Grover Demo] Most likely index {found_idx} -> {demo_candidates[found_idx]['name']}") # Choses the first vulnerable package found.
            print("[Grover Demo] Counts:", counts)

    elapsed = time.time() - start
    print(f"\nSummary: total vulnerable packages = {total}")
    print(f"Time elapsed: {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
