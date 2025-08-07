import paramiko
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import dimod
import neal

debian_fails = 0
debian_successes = 0

def load_nvd_data(path="all_cves_by_date.json"):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    flat_map = {}
    for year_items in data.values():
        for item in year_items:
            cid = item.get("id")
            desc = item.get("description", "")
            raw = item.get("raw", {})
            impact = raw.get("impact", {})
            bm3 = impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
            bm2 = impact.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore")
            score = bm3 or bm2 or 0.0
            flat_map[cid] = {"description": desc, "score": score}
    return flat_map

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    r = requests.get(url); r.raise_for_status()
    return r.json()

def get_debian_cves(data, pkg):
    global debian_fails, debian_successes
    if pkg not in data:
        debian_fails += 1
        return None
    debian_successes += 1
    return list(data[pkg].keys())

def prioritize_cves(cve_list):
    bqm = dimod.BinaryQuadraticModel({}, {}, 0.0, dimod.BINARY)
    for entry in cve_list:
        bqm.add_variable(entry["id"], entry["score"])
    sampler = neal.SimulatedAnnealingSampler()
    sample_set = sampler.sample(bqm, num_reads=100)
    assignment = sample_set.first.sample
    return [e for e in cve_list if assignment.get(e["id"], 0) == 1]

def debian_method(installs):
    tracker = get_debian_tracker()
    nvd_map = load_nvd_data()
    for pkg in installs:
        raw = get_debian_cves(tracker, pkg["name"])
        pkg["cves"] = raw or []
        if raw:
            details = []
            for cve in raw:
                info = nvd_map.get(cve)
                if info and info["description"]:
                    details.append({
                        "id": cve,
                        "description": info["description"].strip(),
                        "score": info["score"]
                    })
            pkg["cve_details"] = details
        else:
            pkg["cve_details"] = []
    all_described = [d for pkg in installs for d in pkg["cve_details"]]
    prioritized = prioritize_cves(all_described)
    output = {
        "described_cves": all_described,
        "prioritized_cves": prioritized,
        "packages": installs
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    for e in prioritized:
        print(f"{e['id']}: {e['description']}")
    print(f"Number of successful matches in Debian: {debian_successes}")
    print(f"Number of failed matches in Debian: {debian_fails}")

def get_installs(ip, username="msfadmin", password="msfadmin"):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command("dpkg -l")
    out = stdout.read().decode("utf-8")
    ssh.close()
    with open("installed.txt", "w", encoding="utf-8") as f:
        f.write(out)
    return out

def parse_installs(text):
    pkgs = []
    for line in text.splitlines():
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
    with open("ip", "r") as f:
        ip = f.read().strip()
    get_installs(ip)
    with open("installed.txt", "r") as f:
        text = f.read()
    installs = parse_installs(text)
    debian_method(installs)

if __name__ == "__main__":
    main()
