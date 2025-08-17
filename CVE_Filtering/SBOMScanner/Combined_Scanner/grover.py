#!/usr/bin/env python3
import os
import json
import re
import math
import time
import requests
from collections import defaultdict
from packaging import version as packaging_version
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

INSTALLED_FILE = "installed.txt"
UBUNTU_JSON = "ubuntu_cves.json"  # local Ubuntu CVE DB (best-effort format)
NVD_JSON = "all_cves.json"        # local NVD JSON (optional)
DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
OUTPUT_JSON = "combined_results.json"

MAX_GROVER_CANDIDATES = 256  # cap for safety (simulation cost)

def parse_installed_packages(path=INSTALLED_FILE):
    packages = []
    if not os.path.exists(path):
        return packages
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    packages.append({'name': parts[1], 'version': parts[2]})
    return packages

def load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)

def strip_ubuntu_suffix(v):
    return re.split(r'-ubuntu\d+$', v) and re.sub(r'-ubuntu\d+$', '', v) or v

def is_ver_less(installed, fixed):
    if not fixed:
        return False
    try:
        return packaging_version.parse(installed) < packaging_version.parse(fixed)
    except Exception:
        try:
            return packaging_version.parse(strip_ubuntu_suffix(installed)) < packaging_version.parse(fixed)
        except Exception:
            return False

def quick_candidate_check(pkg, ubuntu_db, debian_db, nvd_index):
    name = pkg['name']
    ver = pkg['version']
    # Ubuntu quick: look up by source package or by scanning entries
    if ubuntu_db:
        if name in ubuntu_db:
            entries = ubuntu_db[name]
            for cve_id, details in entries.items():
                # try to find fixed version in different structures
                fixed = details.get('fixed_version') or details.get('fixed') or None
                if not fixed:
                    # older Ubuntu JSON may store patches -> search 'patches'
                    patches = details.get('patches') or {}
                    for psrc, pinfo in patches.items():
                        # pinfo may be dict of releases
                        for r, rd in (pinfo.items() if isinstance(pinfo, dict) else []):
                            note = rd.get('note') or rd.get('version') or None
                            if note and is_ver_less(strip_ubuntu_suffix(ver), note):
                                return True
                else:
                    if is_ver_less(strip_ubuntu_suffix(ver), fixed):
                        return True
        else:
            # fallback: search descriptions for package name
            for _, details in ubuntu_db.items():
                desc = (details.get('description') or '').lower() if isinstance(details, dict) else ''
                if name.lower() in desc:
                    return True
    # Debian quick
    if debian_db and name in debian_db:
        for cve_id, info in debian_db[name].items():
            for rel, rdata in info.get('releases', {}).items():
                fixed = rdata.get('fixed_version')
                if fixed and is_ver_less(ver, fixed):
                    return True
    # NVD quick via index
    if nvd_index:
        words = set(re.findall(r'\b[a-z0-9\-\+\.]{3,}\b', name.lower()))
        for w in words:
            for entry in nvd_index.get(w, []):
                # crude assumption: presence implies candidate
                return True
    return False

def index_nvd_by_keywords(nvd_raw):
    if not nvd_raw:
        return {}
    idx = defaultdict(list)
    items = nvd_raw.get('CVE_Items') if isinstance(nvd_raw, dict) else nvd_raw
    if items is None:
        return {}
    for it in items:
        desc = ""
        cid = None
        if isinstance(it, dict) and 'cve' in it:
            cid = it['cve'].get('CVE_data_meta', {}).get('ID') or it.get('id')
            desc_parts = it['cve'].get('description', {}).get('description_data', [])
            desc = " ".join(d.get('value','') for d in desc_parts if isinstance(d, dict))
        else:
            cid = it.get('id') or it.get('cve')
            desc = str(it.get('description',''))
        desc = (desc or "").lower()
        for w in set(re.findall(r'\b[a-z0-9\-\+\.]{3,}\b', desc)):
            idx[w].append({'id': cid, 'raw': it, 'description': desc})
    return idx

def build_marked_mask(packages, ubuntu_db, debian_db, nvd_index):
    mask = []
    for pkg in packages:
        if quick_candidate_check(pkg, ubuntu_db, debian_db, nvd_index):
            mask.append(True)
        else:
            mask.append(False)
    return mask

def build_oracle(qc, num_qubits, marked_indices):
    if not marked_indices:
        return
    for idx in marked_indices:
        bits = format(idx, f'0{num_qubits}b')[::-1]  # LSB first matching mcx convention
        zero_inds = [i for i, b in enumerate(bits) if b == '0']
        if zero_inds:
            qc.x(zero_inds)
        if num_qubits == 1:
            qc.z(0)
        else:
            qc.h(num_qubits - 1)
            qc.mcx(list(range(num_qubits - 1)), num_qubits - 1)
            qc.h(num_qubits - 1)
        if zero_inds:
            qc.x(zero_inds)

def grover_prioritize(packages, mask, shots=1024):
    n = len(packages)
    if n == 0:
        return []
    if not any(mask):
        return packages
    if n > MAX_GROVER_CANDIDATES:
        # too big to reasonably simulate; prioritize classically (marked first)
        prioritized = [p for p, m in zip(packages, mask) if m] + [p for p, m in zip(packages, mask) if not m]
        return prioritized
    num_qubits = math.ceil(math.log2(n))
    dim = 2 ** num_qubits
    marked_indices = [i for i, m in enumerate(mask) if m]
    qc = QuantumCircuit(num_qubits, num_qubits)
    qc.h(range(num_qubits))
    build_oracle(qc, num_qubits, marked_indices)
    # diffuser
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
    backend = AerSimulator()
    tqc = transpile(qc, backend)
    job = backend.run(tqc, shots=shots)
    res = job.result()
    counts = res.get_counts()
    best = max(counts, key=counts.get)
    idx = int(best.replace(" ", ""), 2)
    idx = idx % n
    ordered = [packages[idx]] + [packages[i] for i in range(n) if i != idx]
    return ordered

def verify_and_collect(pkg, ubuntu_db, debian_db, nvd_raw):
    name = pkg['name']
    ver = pkg['version']
    cves = []
    # Ubuntu detailed
    if ubuntu_db and name in ubuntu_db:
        for cve_id, details in ubuntu_db[name].items():
            fixed = details.get('fixed_version') or details.get('fixed') or None
            if not fixed:
                # try patches structure
                patches = details.get('patches') or {}
                for psrc, pinfo in patches.items():
                    for rel, rd in (pinfo.items() if isinstance(pinfo, dict) else []):
                        note = rd.get('note') or rd.get('version') or None
                        if note and is_ver_less(strip_ubuntu_suffix(ver), note):
                            cves.append({'source':'ubuntu','cve_id':cve_id,'description':details.get('description',''),'installed_version':ver,'fixed_version':note})
            else:
                if is_ver_less(strip_ubuntu_suffix(ver), fixed):
                    cves.append({'source':'ubuntu','cve_id':cve_id,'description':details.get('description',''),'installed_version':ver,'fixed_version':fixed})
    # Debian detailed
    if debian_db and name in debian_db:
        for cve_id, details in debian_db[name].items():
            for rel, rd in details.get('releases', {}).items():
                fixed = rd.get('fixed_version')
                status = rd.get('status')
                if fixed and status in ('open','resolved','not-fixed','vulnerable'):
                    if is_ver_less(ver, fixed):
                        cves.append({'source':'debian','cve_id':cve_id,'description':details.get('description',''),'installed_version':ver,'fixed_version':fixed})
    # NVD detailed (best-effort)
    if nvd_raw:
        words = set(re.findall(r'\b[a-z0-9\-\+\.]{3,}\b', name.lower()))
        items = []
        if isinstance(nvd_raw, dict) and 'CVE_Items' in nvd_raw:
            items = nvd_raw['CVE_Items']
        elif isinstance(nvd_raw, list):
            items = nvd_raw
        for it in items:
            desc = ""
            cid = None
            if isinstance(it, dict) and 'cve' in it:
                cid = it['cve'].get('CVE_data_meta', {}).get('ID') or it.get('id')
                desc_parts = it['cve'].get('description', {}).get('description_data', [])
                desc = " ".join(d.get('value','') for d in desc_parts if isinstance(d, dict))
            else:
                cid = it.get('id') or it.get('cve')
                desc = str(it.get('description',''))
            if any(w in desc.lower() for w in words):
                # try to inspect configurations for version ranges (best-effort)
                raw = it
                nodes = raw.get('configurations', {}).get('nodes', []) if isinstance(raw, dict) else []
                match_ver = False
                for node in nodes:
                    for cm in node.get('cpe_match', []):
                        start = cm.get('versionStartIncluding') or cm.get('versionStartExcluding')
                        end = cm.get('versionEndIncluding') or cm.get('versionEndExcluding')
                        if not start and not end:
                            match_ver = True
                        else:
                            ok_start = True
                            ok_end = True
                            try:
                                if start:
                                    ok_start = packaging_version.parse(ver) >= packaging_version.parse(start)
                            except Exception:
                                ok_start = False
                            try:
                                if end:
                                    ok_end = packaging_version.parse(ver) <= packaging_version.parse(end)
                            except Exception:
                                ok_end = False
                            if ok_start and ok_end:
                                match_ver = True
                if match_ver:
                    cves.append({'source':'nvd','cve_id':cid,'description':desc,'installed_version':ver,'fixed_version':None,'nvd_raw':it})
    # deduplicate by cve id + source
    seen = set()
    unique = []
    for e in cves:
        key = (e.get('source'), e.get('cve_id'))
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique

def main():
    start = time.time()
    packages = parse_installed_packages()
    if not packages:
        print("[!] No installed packages file or no results.")
        return
    ubuntu_db = load_json(UBUNTU_JSON) or {}
    nvd_raw = load_json(NVD_JSON)
    nvd_index = index_nvd_by_keywords(nvd_raw) if nvd_raw else {}
    try:
        debian_db = requests.get(DEBIAN_TRACKER_URL, timeout=20).json()
    except Exception:
        debian_db = {}

    mask = build_marked_mask(packages, ubuntu_db, debian_db, nvd_index)
    ordered = grover_prioritize(packages, mask)
    results = defaultdict(list)
    for pkg in ordered:
        matches = verify_and_collect(pkg, ubuntu_db, debian_db, nvd_raw)
        if matches:
            results[pkg['name']].extend(matches)

    # write results
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as fh:
        json.dump(results, fh, indent=2)

    ucount = sum(1 for vs in results.values() for c in vs if c.get('source')=='ubuntu')
    dcount = sum(1 for vs in results.values() for c in vs if c.get('source')=='debian')
    ncount = sum(1 for vs in results.values() for c in vs if c.get('source')=='nvd')
    total_pkgs = len(packages)
    vuln_pkgs = len(results)

    print(f"Total packages scanned: {total_pkgs}")
    print(f"Vulnerable packages found: {vuln_pkgs}")
    print(f"Ubuntu CVE matches: {ucount}")
    print(f"Debian CVE matches: {dcount}")
    print(f"NVD CVE matches: {ncount}")
    print(f"Scan complete in {time.time() - start:.2f} seconds.")

if __name__ == '__main__':
    main()
