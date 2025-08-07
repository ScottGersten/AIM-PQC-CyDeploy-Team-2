import paramiko
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import dimod
from dwave.system import DWaveSampler, EmbeddingComposite


#"""
#to run you need to first install "pip install paramiko requests numpy dwave-ocean-sdk
#- I added load_nvd_data(path) to read our local NVD JSON files
#- I made a cve_map dict to get each CVE’s description and base score
#- I swapped out the online lookups for fetch_cve_descriptions_from_nvd_file that uses cve_map
#- I grabbed the CVSS v3 base score in load_nvd_data (default 0.0 if not found)
#- I wrote build_qubo(cves, penalty) to turn scores into a QUBO (–score on the diagonal, small penalty off-diagonal)
#- I wrote prioritize_cves(details) to run that QUBO on D-Wave and pick the top CVEs
#- I updated debian_method to use the offline data and then call prioritize_cves()
#- I added a "prioritized" list to results.json and print those CVE IDs at the end
#"""



debian_fails = 0
debian_successes = 0

def load_nvd_data(path="all_cves_by_date.json"):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    nvd_map = {}
    for year_data in data.values():
        for item in year_data:
            cve_id = item["id"]
            desc = item["description"]
            raw = item["raw"]
            score = raw.get("impact", {}) \
                       .get("baseMetricV3", {}) \
                       .get("cvssV3", {}) \
                       .get("baseScore", 0.0)
            nvd_map[cve_id] = {"description": desc, "score": score}
    return nvd_map

def fetch_cve_descriptions_from_nvd_file(cve_list, nvd_map):
    results = []
    for c in cve_list:
        info = nvd_map.get(c)
        if info:
            results.append({"id": c, "description": info["description"], "score": info["score"]})
    return results

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    resp = requests.get(url); resp.raise_for_status()
    return resp.json()

def get_debian_cves(data, pkg):
    global debian_fails, debian_successes
    if pkg not in data:
        debian_fails += 1
        return None
    debian_successes += 1
    return list(data[pkg].keys())

def build_qubo(cves, penalty=1.0):
    Q = {}
    for e in cves:
        i = e["id"]
        score = e["score"]
        Q[(i, i)] = -score
    ids = [e["id"] for e in cves]
    for i in range(len(ids)):
        for j in range(i+1, len(ids)):
            Q[(ids[i], ids[j])] = penalty
    return Q

def prioritize_cves(cve_details):
    Q = build_qubo(cve_details)
    sampler = EmbeddingComposite(DWaveSampler())
    sampleset = sampler.sample_qubo(Q, num_reads=100)
    best = sampleset.first.sample
    return [c for c, v in best.items() if v == 1]

def debian_method(installs):
    data = get_debian_tracker()
    nvd_map = load_nvd_data()
    for pkg in installs:
        raw = get_debian_cves(data, pkg["name"])
        pkg["cves"] = raw or []
        if raw:
            details = fetch_cve_descriptions_from_nvd_file(raw, nvd_map)
            pkg["cve_details"] = details
        else:
            pkg["cve_details"] = []
    all_described = []
    for pkg in installs:
        all_described.extend(pkg["cve_details"])
    prioritized = prioritize_cves(all_described)
    output = {
        "described_cves": all_described,
        "packages": installs,
        "prioritized": prioritized
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print("\nPrioritized CVEs:", prioritized)
    print(f"Number of successful matches in Debian: {debian_successes}")
    print(f"Number of failed matches in Debian: {debian_fails}")

def get_installs(ip, username="msfadmin", password="msfadmin"):
    ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command("dpkg -l")
    output = stdout.read().decode("utf-8"); ssh.close()
    with open("installed.txt", "w", encoding="utf-8") as f: f.write(output)
    return output

def parse_installs(installs):
    pkgs = []
    for line in installs.splitlines():
        if line.startswith("ii"):
            parts = line.split()
            pkgs.append({
                "name": parts[1],
                "version": parts[2],
                "description": " ".join(parts[3:]),
                "cves": [],
                "cve_details": []
            })
    return pkgs

def main():
    with open("ip", "r") as f: ip = f.read().strip()
    get_installs(ip)
    with open("installed.txt", "r") as f: text = f.read()
    installs = parse_installs(text)
    debian_method(installs)

if __name__ == "__main__":
    main()
