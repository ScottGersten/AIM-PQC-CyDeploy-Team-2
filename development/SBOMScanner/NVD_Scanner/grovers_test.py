import json
import math
import paramiko
import requests
from qiskit import QuantumCircuit, Aer, transpile
from collections import Counter

debian_fails = 0
debian_successes = 0

# this function loads the big offline NVD file from disk
# x: open the file
# y: make a map from CVE -> {description, score}
# z: return that map so other code can use it fast
def load_nvd_data(path="all_cves_by_date.json"):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    nvd_map = {}
    for year_list in data.values():
        for item in year_list:
            cve_id = item.get("id")
            desc = item.get("description") or ""
            raw = item.get("raw", {})
            score = extract_cvss_from_raw(raw)
            if cve_id:
                nvd_map[cve_id] = {"description": desc, "score": score}
    return nvd_map

# this function pulls a CVSS score out of the raw NVD object
# x: try CVSS v3 first
# y: if no v3, try CVSS v2
# z: if nothing, return None
def extract_cvss_from_raw(raw):
    try:
        v3 = raw.get("impact", {}).get("baseMetricV3", {})
        if "cvssV3" in v3:
            return v3["cvssV3"].get("baseScore")
        # some feeds store v3 directly at top of baseMetricV3
        if "impactScore" in v3 and "exploitabilityScore" in v3:
            # not a base score, so skip unless cvssV3 exists
            pass
    except Exception:
        pass
    try:
        v2 = raw.get("impact", {}).get("baseMetricV2", {})
        if "cvssV2" in v2:
            return v2["cvssV2"].get("baseScore")
    except Exception:
        pass
    return None

# this function returns details (desc + score) for a list of CVEs using the offline map
# x: loop over CVEs we care about
# y: if we have info in nvd_map, keep it
# z: drop ones with no description (we only want useful info)
def fetch_cve_details_from_nvd_file(cve_list, nvd_map):
    out = []
    for cve in cve_list:
        info = nvd_map.get(cve)
        if info and info.get("description"):
            out.append({"id": cve, "description": info["description"], "score": info.get("score")})
    return out

# this function gets Debian’s big JSON
# x: download the one big file
# y: raise if web is down (so we know)
# z: return the JSON
def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

# this function finds which CVEs Debian lists for a package
# x: check if package exists in Debian tracker
# y: count success or fail so we can print numbers
# z: return the list of CVE IDs for that package
def get_debian_cves(data, pkg):
    global debian_fails, debian_successes
    if pkg not in data:
        debian_fails += 1
        return None
    debian_successes += 1
    return list(data[pkg].keys())

# ===== Grover helpers (simple local simulator) =====
# we do Grover on a small set (8 or 16) because simulators are slow on big sets

# this function builds an oracle that "marks" (flips phase of) selected indexes
# x: for each marked index, we flip the phase on that basis state
# y: we do it by matching the bit pattern with X gates, then a multi-control-Z trick
# z: we unflip the X gates to clean up
def build_oracle(n_qubits, marked_indices):
    qc = QuantumCircuit(n_qubits)
    for idx in marked_indices:
        bits = format(idx, f"0{n_qubits}b")
        for i, b in enumerate(reversed(bits)):
            if b == '0':
                qc.x(i)
        qc.h(n_qubits - 1)
        controls = list(range(n_qubits - 1))
        if controls:
            qc.mcx(controls, n_qubits - 1)
        else:
            qc.z(n_qubits - 1)
        qc.h(n_qubits - 1)
        for i, b in enumerate(reversed(bits)):
            if b == '0':
                qc.x(i)
    return qc

# this function builds the "diffuser" which amplifies the marked states
# x: put H on all qubits
# y: do phase flip on |000...0> (same trick as oracle but on zero state)
# z: put H on all qubits again
def build_diffuser(n_qubits):
    qc = QuantumCircuit(n_qubits)
    for i in range(n_qubits):
        qc.h(i)
        qc.x(i)
    qc.h(n_qubits - 1)
    controls = list(range(n_qubits - 1))
    if controls:
        qc.mcx(controls, n_qubits - 1)
    else:
        qc.z(n_qubits - 1)
    qc.h(n_qubits - 1)
    for i in range(n_qubits):
        qc.x(i)
        qc.h(i)
    return qc

# this function runs Grover to find a high-priority CVE from a small sample
# x: pick a small set of CVEs (already passed in), each has a score
# y: mark the indexes where score >= threshold (these are “good answers”)
# z: run Grover loops to find one of the “good answers”
def run_grover_on_cves(sample_items, threshold=7.0):
    N = len(sample_items)
    if N == 0:
        return None

    # number of qubits we need so we can index the items
    n_qubits = math.ceil(math.log2(N))
    size = 2 ** n_qubits

    # pad with fake items so size is power of two
    padded = list(sample_items)
    while len(padded) < size:
        padded.append({"id": f"PAD-{len(padded)}", "description": "", "score": -1.0})

    # choose which indexes are "marked" (score >= threshold)
    marked = [i for i, it in enumerate(padded) if (it.get("score") or 0) >= threshold]
    if not marked:
        # if nothing is above threshold, just pick the top score
        best = max(sample_items, key=lambda x: (x.get("score") or 0))
        return best

    # Grover iteration count (simple formula)
    r = max(1, int(round((math.pi / 4) * math.sqrt(size / max(1, len(marked))))))

    # make the circuit: start in equal superposition
    qc = QuantumCircuit(n_qubits)
    for q in range(n_qubits):
        qc.h(q)

    oracle = build_oracle(n_qubits, marked)
    diffuser = build_diffuser(n_qubits)

    # apply Grover iterations
    for _ in range(r):
        qc.append(oracle.to_gate(), range(n_qubits))
        qc.append(diffuser.to_gate(), range(n_qubits))

    # measure all qubits
    qc.measure_all()

    # run on local simulator
    backend = Aer.get_backend("aer_simulator")
    tqc = transpile(qc, backend)
    res = backend.run(tqc, shots=2048).result()
    counts = res.get_counts()

    # pick the most common bitstring
    best_bits, _ = Counter(counts).most_common(1)[0]
    best_idx = int(best_bits, 2)
    best_item = padded[best_idx]

    # if we hit a PAD, just return top score from the real list
    if best_item["id"].startswith("PAD-"):
        best_item = max(sample_items, key=lambda x: (x.get("score") or 0))
    return best_item

# ===== Your existing Debian + SSH pieces =====

# this function talks to the VM and gets installed packages
# x: SSH into the box
# y: run dpkg -l to list packages
# z: save the output and return it
def get_installs(ip, username="msfadmin", password="msfadmin"):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command("dpkg -l")
    output = stdout.read().decode("utf-8")
    ssh.close()
    with open("installed.txt", "w", encoding="utf-8") as f:
        f.write(output)
    return output

# this function parses the dpkg output into a list of package objects
# x: read each line
# y: keep lines that start with "ii" (installed)
# z: store name/version/desc so later we can add CVEs
def parse_installs(installs):
    packages = []
    for line in installs.splitlines():
        if line.startswith("ii"):
            parts = line.split()
            packages.append({
                "name": parts[1],
                "version": parts[2],
                "description": " ".join(parts[3:]),
                "cves": [],
                "cve_details": []
            })
    return packages

# this function is the main Debian CVE join + Grover flow
# x: get Debian CVEs for each package
# y: attach NVD descriptions+scores from your offline file
# z: run Grover on a small top set to pick a high priority CVE
def debian_method(installs):
    data = get_debian_tracker()
    nvd_map = load_nvd_data("all_cves_by_date.json")

    for pkg in installs:
        raw_ids = get_debian_cves(data, pkg["name"]) or []
        pkg["cves"] = raw_ids
        if raw_ids:
            details = fetch_cve_details_from_nvd_file(raw_ids, nvd_map)
            pkg["cve_details"] = details
        else:
            pkg["cve_details"] = []

    all_described = []
    for pkg in installs:
        all_described.extend(pkg["cve_details"])

    # print CVEs and short info
    print("\nCVE Descriptions for this VM:")
    for entry in all_described:
        sc = entry.get("score")
        sc_txt = f" | score={sc}" if sc is not None else ""
        print(f"{entry['id']}: {entry['description'].strip()[:200]}{sc_txt}")

    # pick a small sample for Grover (top 8 by score)
    sample = sorted(
        [e for e in all_described if e.get("score") is not None],
        key=lambda x: x["score"],
        reverse=True
    )[:8]

    grover_pick = run_grover_on_cves(sample, threshold=7.0) if sample else None
    if grover_pick:
        print("\nGrover picked this high priority CVE:")
        print(f"{grover_pick['id']} | score={grover_pick.get('score')} | {grover_pick['description'][:300]}")

    # write full results
    output = {
        "described_cves": all_described,
        "packages": installs,
        "grover_pick": grover_pick
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\nNumber of successful matches in Debian: {debian_successes}")
    print(f"Number of failed matches in Debian: {debian_fails}")

def main():
    with open("ip.txt", "r") as f:
        ip = f.read().strip()
    get_installs(ip)
    with open("installed.txt", "r") as f:
        text = f.read()
    installs = parse_installs(text)
    debian_method(installs)

if __name__ == "__main__":
    main()
