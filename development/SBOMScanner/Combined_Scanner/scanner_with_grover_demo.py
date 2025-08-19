
import os, json, re, time, math, requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from packaging import version as packaging_version

# Quantum (Grover demo) 
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator


# CONFIG

INSTALLED_FILE = "installed.txt"
UBUNTU_JSON = "ubuntu_cves.json"
NVD_JSON = "all_cves.json"
DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
OUTPUT_JSON = "grover_results.json"

MAX_GROVER_CANDIDATES = 256
GROVER_SHOTS = 1024


# PARSERS / LOADERS

def parse_installed_packages(path=INSTALLED_FILE):
    pkgs = []
    if not os.path.exists(path):
        print(f"[!] {path} not found.")
        return pkgs
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("ii"):
                parts = line.split()
                if len(parts) >= 3:
                    pkgs.append({
                        "name": parts[1].lower(),
                        "version": parts[2].strip(),
                        "cves": [],
                    })
    return pkgs

def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def get_debian_tracker():
    try:
        r = requests.get(DEBIAN_TRACKER_URL, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[!] Debian tracker fetch failed: {e}")
        return {}

def _parse(v):
    try:
        return packaging_version.parse(v)
    except Exception:
        return None

def is_version_in_range(installed, start_incl=None, start_excl=None, end_incl=None, end_excl=None):
    v = _parse(installed)
    if v is None:
        return False

    start_incl_v = _parse(start_incl) if start_incl else None
    start_excl_v = _parse(start_excl) if start_excl else None
    end_incl_v   = _parse(end_incl)   if end_incl else None
    end_excl_v   = _parse(end_excl)   if end_excl else None

    if start_incl_v and v < start_incl_v: return False
    if start_excl_v and v <= start_excl_v: return False
    if end_incl_v   and v > end_incl_v:   return False
    if end_excl_v   and v >= end_excl_v:  return False

    return True


# UBUNTU: Build heuristic index

_AFFECT_PATTERNS = [
    r'(\b[\w\-\+\.]+)\s+(?:before|prior to|<|<=|less than)\s+([\w\d\.\-\:\+~]+)',
    r'(\b[\w\-\+\.]+)\s+(?:is\s+)?fixed in version\s+([\w\d\.\-\:\+~]+)',
    r'^(\S+)\s+-\s+([\w\d\.\-\:\+~]+)',
]

def normalize_affected(desc):
    matches = []
    for pat in _AFFECT_PATTERNS:
        matches += re.findall(pat, desc, flags=re.IGNORECASE | re.MULTILINE)
    return matches

def index_ubuntu_by_pkg(ubuntu_entries):
    idx = defaultdict(list)
    if not ubuntu_entries:
        return idx
    for entry in (ubuntu_entries if isinstance(ubuntu_entries, list) else []):
        desc_raw = entry.get("description", "")
        if isinstance(desc_raw, list):
            desc = " ".join(d.get("value", "") for d in desc_raw if isinstance(d, dict))
        else:
            desc = str(desc_raw)
        desc = desc.lower()
        for name, fixed in normalize_affected(desc):
            idx[name].append((fixed, entry))
    return idx


# NVD keyword index by package name

def index_nvd_by_pkg(nvd):
    idx = defaultdict(list)
    items = []
    if isinstance(nvd, dict) and "CVE_Items" in nvd:
        items = nvd["CVE_Items"]
    elif isinstance(nvd, list):
        items = nvd
    for it in items:
        try:
            cve_id = it["cve"]["CVE_data_meta"]["ID"]
            desc = " ".join(d.get("value", "") for d in it["cve"]["description"]["description_data"])
            desc = desc.lower()
            nodes = it.get("configurations", {}).get("nodes", [])
            for node in nodes:
                for cpe in node.get("cpe_match", []):
                    cpe_uri = cpe.get("cpe23Uri", "").lower()
                    if cpe.get("vulnerable", False):
                        # extract package name from cpe_uri
                        m = re.match(r"cpe:2\.3:[aho]:[^:]*:([^:]+):", cpe_uri)
                        if m:
                            pkg_name = m.group(1)
                            idx[pkg_name].append(it)
        except Exception:
            continue
    return idx


# MATCHERS (strict version-aware)

def match_ubuntu(pkg, ubuntu_index):
    out = []
    name, ver = pkg["name"], pkg["version"]
    for fixed, entry in ubuntu_index.get(name, []):
        v_inst, v_fix = _parse(ver), _parse(fixed)
        if v_inst and v_fix and v_inst < v_fix:
            desc = entry.get("description") or entry.get("title")
            if desc:
                out.append({
                    "source": "ubuntu",
                    "cve_id": entry.get("id") or entry.get("cve_id"),
                    "title": entry.get("title"),
                    "description": desc,
                })
    return out

def match_debian(pkg, debian_db):
    out = []
    name, ver = pkg["name"], pkg["version"]
    if name not in debian_db:
        return out
    seen_cve = set()
    for cve_id, cve_info in debian_db[name].items():
        if str(cve_id).startswith("TEMP") or cve_id in seen_cve:
            continue
        releases = cve_info.get("releases", {})
        for rel, rdata in releases.items():
            fixed = rdata.get("fixed_version")
            status = (rdata.get("status") or "").lower()
            if not fixed:
                continue
            if status in ("open", "resolved", "not-fixed", "vulnerable", "undetermined"):
                v_inst, v_fix = _parse(ver), _parse(fixed)
                if v_inst and v_fix and v_inst < v_fix:
                    if cve_info.get("description"):
                        out.append({
                            "source": "debian",
                            "cve_id": cve_id,
                            "description": cve_info.get("description"),
                            "release": rel,
                            "fixed_version": fixed
                        })
                        seen_cve.add(cve_id)
    return out

def match_nvd(pkg, nvd_indexed):
    out = []
    name, ver = pkg["name"], pkg["version"]
    for it in nvd_indexed.get(name, []):
        try:
            cve_id = it["cve"]["CVE_data_meta"]["ID"]
            conf = it.get("configurations", {})
            nodes = conf.get("nodes", [])
            matched = False
            for node in nodes:
                for cpe in node.get("cpe_match", []):
                    cpe_uri = cpe.get("cpe23Uri", "").lower()
                    if name in cpe_uri and cpe.get("vulnerable", False):
                        if is_version_in_range(
                            ver,
                            cpe.get("versionStartIncluding"),
                            cpe.get("versionStartExcluding"),
                            cpe.get("versionEndIncluding"),
                            cpe.get("versionEndExcluding"),
                        ):
                            matched = True
                            break
                if matched: break
            if matched:
                desc = " ".join(d.get("value", "") for d in it["cve"]["description"]["description_data"])
                if desc.strip():
                    out.append({
                        "source": "nvd",
                        "cve_id": cve_id,
                        "description": desc
                    })
        except Exception:
            continue
    return out

def verify_and_collect(pkg, ubuntu_index, debian_db, nvd_indexed):
    confirmed = []
    confirmed.extend(match_ubuntu(pkg, ubuntu_index))
    confirmed.extend(match_debian(pkg, debian_db))
    confirmed.extend(match_nvd(pkg, nvd_indexed))
    confirmed = [c for c in confirmed if c.get("description") and c["description"].strip()]

    seen = set()
    deduped = []
    for c in confirmed:
        cid = c.get("cve_id") or ("ubuntu-" + (c.get("title") or ""))
        if cid and cid not in seen:
            seen.add(cid)
            deduped.append(c)
    pkg["cves"] = deduped
    return deduped


from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
import math

def build_oracle(qc, num_qubits, marked_indices):
    """Mark the target indices in the Grover circuit."""
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
        rest  = [p for p, m in zip(packages, marked_mask) if not m]
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

    # Only seed_simulator is valid now
    backend = AerSimulator(seed_simulator=seed)
    tqc = transpile(qc, backend)
    res = backend.run(tqc, shots=shots).result().get_counts()

    best_state = max(sorted(res), key=res.get)
    top_idx = int(best_state, 2) % n

    top = packages[top_idx]
    rest = [packages[i] for i in range(n) if i != top_idx]
    return [top] + rest


def prioritize_with_grover(confirmed_vuln_pkgs):
    if not confirmed_vuln_pkgs:
        return []

    # Score = number of CVEs for each package
    scores = [len(p["cves"]) for p in confirmed_vuln_pkgs]
    max_score = max(scores) if scores else 0
    mask = [1 if s == max_score else 0 for s in scores]

    # Grover picks the top candidate by the highest CVE count
    top = grover_simulate_order(confirmed_vuln_pkgs, mask, seed=12345)[0]

    # Sort the rest by CVE count (descending)
    rest = sorted(
        [p for p in confirmed_vuln_pkgs if p != top],
        key=lambda p: len(p["cves"]),
        reverse=True
    )

    return [top] + rest


def main():
    t0 = time.time()
    packages = parse_installed_packages()
    print(f"[i] Installed packages parsed: {len(packages)}")
    if not packages: return

    ubuntu_raw = load_json(UBUNTU_JSON) or []
    nvd_raw = load_json(NVD_JSON) or {}
    debian_db = get_debian_tracker() or {}
    ubuntu_index = index_ubuntu_by_pkg(ubuntu_raw)
    nvd_indexed = index_nvd_by_pkg(nvd_raw)

    print("Verifying packages against Ubuntu/Debian/NVD (version-aware)...")
    with ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda p: verify_and_collect(p, ubuntu_index, debian_db, nvd_indexed), packages))

    confirmed = [p for p in packages if p.get("cves")]
    print(f"Confirmed vulnerable packages: {len(confirmed)}")


   
    ordered = prioritize_with_grover(confirmed)

    print("\n[Grover Prioritization Results]")
    if ordered:
        top = ordered[0]
        top_cves = ", ".join(m.get("cve_id") or (m.get("title") or "unknown") for m in top["cves"])
        print(f" Top candidate (Grover-selected): {top['name']} {top['version']}")
        print(" Full prioritized order (confirmed vulnerable only):")
        for i, pkg in enumerate(ordered, 1):
            cves = ", ".join(m.get("cve_id") or (m.get("title") or "unknown") for m in pkg["cves"])
            print(f"  {i}. {pkg['name']} {pkg['version']} -> {len(pkg['cves'])}") 
    else:
        print(" No confirmed vulnerable packages to prioritize.")

    with open(OUTPUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(confirmed, fh, indent=2)

    print(f"\n[i] Saved confirmed CVEs to {OUTPUT_JSON}")
    print(f"[i] Done in {time.time() - t0:.2f}s.")

if __name__ == "__main__":
    main()
