import os
import glob
import json
import paramiko
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


debian_fails = 0
debian_successes = 0

def build_offline_index(folder="all", workers=8):
    paths = glob.glob(os.path.join(folder, "*.json"))

    def load_one(path):
        rec = json.loads(open(path, encoding="utf-8").read())
        
        cve_id = rec.get("id")
        desc = rec.get("summary") or rec.get("details")
      
        if not desc:
            for d in rec.get("containers", {}).get("cna", {}).get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value")
                    break
        return cve_id, desc

    index = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for cve_id, desc in ex.map(load_one, paths):
            if cve_id and desc:
                index[cve_id] = desc
    return index

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    r = requests.get(url)
    r.raise_for_status()
    return r.json()

def get_debian_cves(data, pkg_name):
    
    global debian_fails, debian_successes
    if pkg_name not in data:
        debian_fails += 1
        return []
    debian_successes += 1
    return list(data[pkg_name].keys())

def debian_method(installs, cve_index):
    
    tracker = get_debian_tracker()

    for pkg in installs:
        raw = get_debian_cves(tracker, pkg["name"])
        pkg["cves"] = raw
        
        pkg["cve_details"] = [
            {"id": c, "description": cve_index[c]}
            for c in raw
            if c in cve_index
        ]

    
    all_described = [d for pkg in installs for d in pkg["cve_details"]]

    
    output = {
        "described_cves": all_described,
        "packages": installs
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    
    print(f"Number of successful matches in Debian: {debian_successes}")
    print(f"Number of failed matches in Debian: {debian_fails}")
    print("\nCVE Descriptions for this VM:")
    for entry in all_described:
        print(f"{entry['id']}: {entry['description']}")
    print(f"Number of successful matches in Debian: {debian_successes}")
    print(f"Number of failed matches in Debian: {debian_fails}")

def get_installs(ip, username="msfadmin", password="msfadmin"):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command("dpkg -l")
    text = stdout.read().decode("utf-8")
    ssh.close()
    with open("installed.txt", "w", encoding="utf-8") as f:
        f.write(text)
    return text

def parse_installs(installed_txt):
    
    pkgs = []
    for line in installed_txt.splitlines():
        if line.startswith("ii"):
            parts = line.split()
            pkgs.append({
                "name": parts[1],
                "version": parts[2],
                "description": " ".join(parts[3:])
            })
    return pkgs

def main():
    
    cve_index = build_offline_index(folder="all", workers=8)

    
    with open("ip.txt", "r") as f:
        ip = f.read().strip()
    get_installs(ip)
    with open("installed.txt", "r") as f:
        txt = f.read()
    installs = parse_installs(txt)

    
    debian_method(installs, cve_index)

if __name__ == "__main__":
    main()
