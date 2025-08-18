import paramiko
import requests
import json
import dimod

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
            flat_map[cid] = {"description": desc, "score": float(score) if score is not None else 0.0}
    return flat_map

def fetch_cve_descriptions_from_nvd_file(cve_list, nvd_map):
    results = []
    for cve in cve_list:
        info = nvd_map.get(cve)
        if info and info.get("description"):
            results.append({"id": cve, "description": info["description"].strip(), "score": info.get("score", 0.0)})
    return results

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    return resp.json()

def get_debian_cves(data, pkg):
    global debian_fails, debian_successes
    if pkg not in data:
        debian_fails += 1
        return None
    debian_successes += 1
    return list(data[pkg].keys())

def prioritize_cves(cve_list, top_k=10, penalty=None, sample_cap=50):
    items = [e for e in cve_list if isinstance(e.get("score"), (int, float))]
    if not items or top_k <= 0:
        return []
    items = sorted(items, key=lambda e: e["score"], reverse=True)[:sample_cap]
    N = len(items)
    ids = [e["id"] for e in items]
    weights = {e["id"]: float(e["score"]) for e in items}
    max_w = max(weights.values()) if weights else 1.0
    A = penalty or (max_w + 1.0)
    bqm = dimod.BinaryQuadraticModel({}, {}, 0.0, dimod.BINARY)
    lin_bias = A * (1 - 2 * top_k)
    for vid in ids:
        bqm.add_variable(vid, -weights[vid] + lin_bias)
    for i in range(N):
        for j in range(i + 1, N):
            bqm.add_interaction(ids[i], ids[j], 2 * A)
    try:
        import neal
        sampler = neal.SimulatedAnnealingSampler()
        sampleset = sampler.sample(bqm, num_reads=200)
    except Exception:
        from dimod.reference.samplers import ExactSolver
        sampleset = ExactSolver().sample(bqm)
    best = sampleset.first.sample
    chosen = [e for e in items if best.get(e["id"], 0) == 1]
    if len(chosen) != min(top_k, N):
        chosen = items[:min(top_k, N)]
    return chosen

def debian_method(installs, top_k=10, sample_cap=50):
    data = get_debian_tracker()
    nvd_map = load_nvd_data("all_cves_by_date.json")
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
    prioritized = prioritize_cves(all_described, top_k=top_k, sample_cap=sample_cap)
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
    output = stdout.read().decode("utf-8")
    ssh.close()
    with open("installed.txt", "w", encoding="utf-8") as f:
        f.write(output)
    return output

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

def main():
    with open("ip", "r") as f:
        ip = f.read().strip()
    get_installs(ip)
    with open("installed.txt", "r") as f:
        text = f.read()
    installs = parse_installs(text)
    debian_method(installs, top_k=10, sample_cap=50)

if __name__ == "__main__":
    main()