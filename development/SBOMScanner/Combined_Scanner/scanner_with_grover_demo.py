import os
import re
import json
import time
import math
import requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from packaging import version as packaging_version
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator



# CONFIG

INSTALLED_FILE = "installed.txt"
UBUNTU_JSON = "ubuntu_cves.json"
NVD_JSON = "all_cves.json"
OUTPUT_JSON = "grover_combined_results.json"

# Grover parameters
MAX_GROVER_CANDIDATES = 256
GROVER_SHOTS = 1024


# PARSERS / LOADERS

def parse_installed_packages(file_path=INSTALLED_FILE):
    packages = []
    if not os.path.exists(file_path):
        print(f"[!] {file_path} not found.")
        return packages
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    packages.append({
                        'name': parts[1].lower(),
                        'version': parts[2].strip(),
                        'cves': []
                    })
    return packages


def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def _parse_version(v):
    try:
        return packaging_version.parse(v)
    except Exception:
        return None


def is_version_vulnerable(installed_version, constraints):
    try:
        inst_ver = packaging_version.parse(installed_version)
        for op, ver in constraints:
            cmp_ver = packaging_version.parse(ver)
            if op == "<" and not (inst_ver < cmp_ver):
                return False
            if op == "<=" and not (inst_ver <= cmp_ver):
                return False
            if op == ">=" and not (inst_ver >= cmp_ver):
                return False
        return True if constraints else False
    except Exception:
        return False



# UBUNTU CVE SCANNER

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
        else:
            desc = str(desc_raw)
        desc = desc.lower()
        for name, ver in normalize_affected(desc):
            index[name].append((ver, cve))
    return index


def match_ubuntu_cves(packages, ubuntu_index):
    def match(pkg):
        matched = []
        for fixed_version, cve in ubuntu_index.get(pkg['name'], []):
            try:
                if packaging_version.parse(pkg['version']) < packaging_version.parse(fixed_version) and cve.get("description"):
                    matched.append({
                        'source': 'ubuntu',
                        'title': cve.get('title'),
                        'description': cve.get('description'),
                        'fixed_version': fixed_version,
                        'installed_version': pkg['version'],
                    })
            except Exception:
                continue
        pkg['cves'] = matched
# DEBIAN CVE SCANNER

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
    for cve_id, cve_info in pkg_data.items():
        if cve_id.startswith("TEMP"):
            continue
        for release, release_data in cve_info.get("releases", {}).items():
            status = release_data.get("status")
            fixed_version = release_data.get("fixed_version")
            if not fixed_version or status in ("not affected", "end-of-life", "ignored", "undetermined"):
                continue
            try:
                inst_ver = packaging_version.parse(installed_version)
                fix_ver = packaging_version.parse(fixed_version)
                # Vulnerable if installed < fixed and description exists
                if inst_ver < fix_ver and cve_id not in seen and cve_info.get("description"):
                    cves.append({
                        "source": "debian",
                        "cve_id": cve_id,
                        "description": cve_info.get("description"),
                        "release": release,
                        "status": status,
                        "fixed_version": fixed_version,
                        "installed_version": installed_version
                    })
                    seen.add(cve_id)

            except Exception:
                continue
    return cves



# NVD CVE SCANNER

def index_nvd_by_keywords(cve_data):
    index = defaultdict(list)
    for entry in cve_data:
        desc = entry.get('description', '').lower()
        for word in re.findall(r'\b[a-z0-9\-\+\.]{3,}\b', desc):
            index[word].append(entry)
    return index


def extract_version_constraints(desc):
    patterns = [
        r"(?:before|prior to|<)\s*([\w\.\-\+~:]+)",
        r"(?:through|<=)\s*([\w\.\-\+~:]+)",
        r"(?:fixed in|>=)\s*([\w\.\-\+~:]+)"
    ]
    constraints = []
    for pat in patterns:
        for match in re.findall(pat, desc, re.IGNORECASE):
            if "before" in pat or "<" in pat or "prior" in pat:
                constraints.append(("<", match))
            elif "through" in pat or "<=" in pat:
                constraints.append(("<=", match))
            elif "fixed in" in pat or ">=" in pat:
                constraints.append((">=", match))
    return constraints


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
            if cve_id in seen_ids or cve_id.startswith("TEMP"):
                continue
            seen_ids.add(cve_id)
            if name in desc:
                constraints = extract_version_constraints(desc)
                if is_version_vulnerable(full_ver, constraints):
                    matched.append({
                        'source': 'nvd',
                        'cve_id': cve_id,
                        'description': entry.get('description', ''),
                        'constraints': constraints
                    })
        pkg['cves'].extend(matched)
    with ThreadPoolExecutor() as executor:
        list(executor.map(match, packages))


# GROVER PRIORITIZATION

def build_oracle(qc, num_qubits, marked_indices):
    for idx in marked_indices:
        bits = format(idx, f'0{num_qubits}b')[::-1]
        zeros = [i for i, b in enumerate(bits) if b == '0']
        if zeros: qc.x(zeros)
        if num_qubits == 1:
            qc.z(0)
        else:
            qc.h(num_qubits - 1)
            qc.mcx(list(range(num_qubits - 1)), num_qubits - 1)
            qc.h(num_qubits - 1)
        if zeros: qc.x(zeros)


def grover_simulate_order(packages, marked_mask, shots=1024, seed=12345):
    n = len(packages)
    if n == 0 or not any(marked_mask):
        return packages[:]
    if n > 256:
        first = [p for p, m in zip(packages, marked_mask) if m]
        rest = [p for p, m in zip(packages, marked_mask) if not m]
        return first + rest
    num_qubits = math.ceil(math.log2(n))
    marked_indices = [i for i, m in enumerate(marked_mask) if m]
    qc = QuantumCircuit(num_qubits, num_qubits)
    qc.h(range(num_qubits))
    build_oracle(qc, num_qubits, marked_indices)
    qc.h(range(num_qubits))
    qc.x(range(num_qubits))
    if num_qubits == 1:
        qc.z(0)
    else:
        qc.h(num_qubits - 1)
        qc.mcx(list(range(num_qubits - 1)), num_qubits - 1)
        qc.h(num_qubits - 1)
    qc.x(range(num_qubits))
    qc.h(range(num_qubits))
    qc.measure(range(num_qubits), range(num_qubits))
    backend = AerSimulator(seed_simulator=seed)
    tqc = transpile(qc, backend)
    res = backend.run(tqc, shots=shots).result().get_counts()
    best_state = max(sorted(res), key=res.get)
    top_idx = int(best_state, 2) % n
    top = packages[top_idx]
    rest = [packages[i] for i in range(n) if i != top_idx]
    return [top] + rest


def prioritize_with_grover(vulnerable_packages):
    if not vulnerable_packages:
        return []
    scores = [len(p['cves']) for p in vulnerable_packages]
    max_score = max(scores)
    mask = [1 if s == max_score else 0 for s in scores]
    top = grover_simulate_order(vulnerable_packages, mask)[0]
    rest = sorted([p for p in vulnerable_packages if p != top],
                  key=lambda p: len(p['cves']), reverse=True)
    return [top] + rest




def main():
    start_time = time.time()
    print("Parsing installed packages...")
    packages = parse_installed_packages()
    print(f"{len(packages)} packages found.")

    ubuntu_pkgs = [p for p in packages if "ubuntu" in p['version'].lower()]
    non_ubuntu_pkgs = [p for p in packages if "ubuntu" not in p['version'].lower()]

    # Ubuntu CVEs
    ubuntu_matches = 0
    if ubuntu_pkgs:
        print("Scanning Ubuntu CVE Database...")
        ubuntu_cves_raw = load_json(UBUNTU_JSON) or []
        ubuntu_index = index_cves_by_package(ubuntu_cves_raw)
        match_ubuntu_cves(ubuntu_pkgs, ubuntu_index)

        # Count actual matches with non-empty descriptions
        for pkg in ubuntu_pkgs:
            pkg['cves'] = [c for c in pkg['cves'] if c.get('description')]
            if pkg['cves']:
                ubuntu_matches += 1

    # Debian CVEs
    debian_matches = 0
    if non_ubuntu_pkgs:
        print("Scanning Debian Security Tracker...")
        debian_data = get_debian_tracker()
        for pkg in non_ubuntu_pkgs:
            seen = set()
            pkg['cves'] = get_debian_cves_for_package(debian_data.get(pkg['name'], {}), pkg['version'], seen)
            if pkg['cves']:
                debian_matches += 1

    # NVD fallback
    fallback_pkgs = [p for p in packages if not p['cves']]
    if fallback_pkgs:
        print("Fallback: scanning NVD...")
        nvd_cves_raw = load_json(NVD_JSON) or []
        nvd_index = index_nvd_by_keywords(nvd_cves_raw)
        match_nvd_cves(fallback_pkgs, nvd_index)

    # Collect vulnerable packages
    vulnerable = [p for p in packages if p['cves']]

    print("\nSummary:")
    print(f"Total vulnerable packages: {len(vulnerable)}")
    print(f"Ubuntu matches: {ubuntu_matches}")
    print(f"Debian matches: {debian_matches}")
    print(f"NVD matches: {sum(1 for p in packages if any(c.get('source') == 'nvd' for c in p['cves']))}")

    # Grover prioritization
    ordered = prioritize_with_grover(vulnerable)
    print("\n[Grover Prioritization]")
    for i, pkg in enumerate(ordered, 1):
        print(f"{i}. {pkg['name']} {pkg['version']} -> {len(pkg['cves'])} CVEs")

    # Save results
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(vulnerable, f, indent=2)

    print(f"\nScan complete in {time.time() - start_time:.2f} seconds. Results saved to {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
