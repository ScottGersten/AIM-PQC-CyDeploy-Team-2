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

INSTALLED_FILE = "installed.txt"  # File containing installed packages
UBUNTU_JSON = "ubuntu_cves.json"  # Ubuntu CVE database
NVD_JSON = "all_cves.json"        # NVD CVE database 
OUTPUT_JSON = "grover_combined_results.json"  # Output file

# Grover parameters
MAX_GROVER_CANDIDATES = 256
GROVER_SHOTS = 1024


def simplify_version(version_str):
    """Removes any suffixes (-, +, ~) to get the base version for comparison."""
    return re.split(r'[-+~]', version_str)[0]


# PARSERS / LOADERS

def parse_installed_packages(file_path=INSTALLED_FILE):
    """
    Parse 'dpkg -l' style installed packages file.
    Returns a list of dicts: {name, version, base_version, cves}.
    """
    packages = []
    if not os.path.exists(file_path):
        print(f"[!] {file_path} not found.")
        return packages
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    full_version = parts[2].strip()
                    base_version = re.split(r'[-+~]', full_version)[0]
                    packages.append({
                        'name': parts[1].lower(),
                        'version': full_version,
                        'base_version': base_version,
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
    """
    Check if installed_version satisfies any version constraints.
    Parses unstructured NVD CVE description to extract version constraints.
    """
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
    """
    Extract package name + affected version from CVE descriptions.
    Handles formats like:
      - pkg - 1.2.3
      - pkg before 2.0.0
      - pkg fixed in version 3.1.4
    """
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
    """
    Index CVEs by package name for fast lookup.
    """
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

def match_package(pkg, cve_index):
    """ Match a single installed package against indexed Ubuntu CVEs. """
    pkg_name = pkg['name']
    base_version = pkg['base_version']
    matched = []
    seen_cves = set()

    candidates = cve_index.get(pkg_name, [])

    for affected_version, cve in candidates:
        try:
            if packaging_version.parse(base_version) < packaging_version.parse(affected_version):
                cve_id = cve.get('cve_id')  
                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    matched.append({
                        'cve_id': cve_id,
                        'affected_pkg': pkg_name,
                        'affected_version': affected_version,
                        'title': cve.get('title', ''),
                        'description': cve.get('description', ''),
                        
                    })
        except Exception:
            continue

    pkg['cves'] = matched
    return matched



def match_ubuntu_cves(packages, cve_entries):
   
    cve_index = index_cves_by_package(cve_entries)
    matched = []

    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda pkg: match_package(pkg, cve_index), packages))

    for m in results:
        matched.extend(m)
    return matched


# DEBIAN CVE SCANNER

debian_fails = 0
debian_successes = 0


def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


def get_debian_cves(data, pkg_name, installed_version):
    """Get CVEs for a specific package from Debian tracker."""
    global debian_fails, debian_successes
    if pkg_name not in data:
        debian_fails += 1
        return []
    debian_successes += 1
    pkg_data = data[pkg_name]
    seen = set()
    return get_debian_cves_for_package(pkg_data, installed_version, seen)


def get_debian_cves_for_package(pkg_data, installed_version, seen):
    """
    Extract CVEs from Debian tracker per package version.
    Checks if installed version < fixed_version and description exists.
    """
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
    """Index NVD entries by keywords from their descriptions for quick search."""
    index = defaultdict(list)
    for entry in cve_data:
        desc = entry.get('description', '').lower()
        for word in re.findall(r'\b[a-z0-9\-\+\.]{3,}\b', desc):
            index[word].append(entry)
    return index


def extract_version_constraints(desc):
    """ Parse unstructured NVD CVE description to extract version constraints. """
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
    """
    Construct a Grover oracle that highlights the important items so the algorithm can focus on them.
    qc: QuantumCircuit
    num_qubits: number of qubits in the circuit
    marked_indices: indices of packages to prioritize
    """
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
    """
    Simulate Grover search to find the top-priority vulnerable package.
    packages: list of vulnerable packages
    marked_mask: list of 1s and 0s indicating which packages are top-priority (1 = top priority and 0 = not top priority)
    Returns a reordered list of packages with the top-priority first.
    """
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
    """
    Prioritize vulnerable packages using Grover-inspired simulation.
    Returns a reordered list: top-priority package first.
    Packages with the highest CVE count are at the top of the list.
    """
    if not vulnerable_packages:
        return []
    
    # Score packages by number of CVEs
    scores = [len(p['cves']) for p in vulnerable_packages]
    max_score = max(scores)
    mask = [1 if s == max_score else 0 for s in scores]
    
    top = grover_simulate_order(vulnerable_packages, mask)[0]
    # Sort the rest in descending order of CVE count
    rest = sorted([p for p in vulnerable_packages if p != top],
                  key=lambda p: len(p['cves']), reverse=True)
    return [top] + rest


# MAIN FUNCTION

def main():
    start_time = time.time()
    print("Parsing installed packages...")
    packages = parse_installed_packages()
    print(f"{len(packages)} packages found.")

    # Separate Ubuntu and non-Ubuntu packages
    ubuntu_pkgs = [p for p in packages if "ubuntu" in p['version'].lower()]
    non_ubuntu_pkgs = [p for p in packages if "ubuntu" not in p['version'].lower()]

    # Ubuntu CVEs
    ubuntu_matches = 0
    if ubuntu_pkgs:
        print("Scanning Ubuntu CVE Database...")
        ubuntu_cves_raw = load_json(UBUNTU_JSON) or []
        match_ubuntu_cves(ubuntu_pkgs, ubuntu_cves_raw)

    # Counts Ubuntu matches
    ubuntu_matches = sum(1 for pkg in ubuntu_pkgs if pkg['cves'])

       
    # Debian CVEs
    debian_matches = 0
    if non_ubuntu_pkgs:
        print("Scanning Debian Security Tracker...")
        debian_data = get_debian_tracker()
        for pkg in non_ubuntu_pkgs:
            pkg['cves'] = get_debian_cves(debian_data, pkg['name'], pkg['version'])
            if pkg['cves']:
                debian_matches += 1


    # NVD fallback for packages not matched by Ubuntu/Debian
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
