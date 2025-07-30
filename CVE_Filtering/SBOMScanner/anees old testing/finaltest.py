import os
import paramiko
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

debian_fails = 0
debian_successes = 0

def load_offline_descriptions(dir_path):
    mapping = {}
    for fn in os.listdir(dir_path):
        if not fn.lower().endswith(".json"):
            continue
        full = os.path.join(dir_path, fn)
        try:
            with open(full, "r", encoding="utf-8") as f:
                data = json.load(f)
            cve_id = data.get("id")
            desc = data.get("summary") or data.get("details")
            if cve_id and desc:
                mapping[cve_id] = desc
        except Exception:
            
            continue
    return mapping

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

def get_debian_cves(data, pkg):
    global debian_fails, debian_successes

    if pkg not in data:
        debian_fails += 1
        return None

    debian_successes += 1
    pkg_data = data[pkg]
    return list(pkg_data.keys())

def debian_method(installs, desc_map):
    data = get_debian_tracker()

    
    for pkg in installs:
        raw = get_debian_cves(data, pkg["name"])
        pkg["cves"] = raw or []

        if raw:
            
            pkg["cve_details"] = [
                {"id": c, "description": desc_map[c]}
                for c in raw
                if c in desc_map
            ]
        else:
            pkg["cve_details"] = []

    
    all_described = []
    for pkg in installs:
        all_described.extend(pkg["cve_details"])

    
    output = {
        "described_cves": all_described,
        "packages": installs
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    
    print(f"Number of successful matches in Debian: {debian_successes}")
    print(f"Number of failed matches in Debian:   {debian_fails}")
    print("\nCVE Descriptions for this VM:")
    for entry in all_described:
        print(f"{entry['id']}: {entry['description']}")

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
    
    desc_map = load_offline_descriptions("all")

    
    with open("ip.txt", "r") as f:
        ip = f.read().strip()
    get_installs(ip)
    with open("installed.txt", "r") as f:
        text = f.read()
    installs = parse_installs(text)

    
    debian_method(installs, desc_map)

if __name__ == "__main__":
    main()
