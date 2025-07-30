import paramiko
import requests
import json
import gzip
import io

# Counters for Debian‐tracker hits/misses
debian_fails = 0
debian_successes = 0

def load_nvd_feed(url):
    r = requests.get(url)
    r.raise_for_status()

    # decompress in memory
    buf = io.BytesIO(r.content)
    with gzip.GzipFile(fileobj=buf) as gz:
        data = json.loads(gz.read().decode("utf-8"))

    mapping = {}
    for entry in data.get("vulnerabilities", []):
        cve_id = entry["cve"]["id"]
        descs = entry["cve"].get("descriptions", [])
        # pick the English description if present
        eng = None
        for d in descs:
            if d.get("lang") == "en":
                eng = d.get("value")
                break
        mapping[cve_id] = eng
    return mapping

def get_debian_tracker():
    url = "https://security-tracker.debian.org/tracker/data/json"
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

def get_debian_cves(data, pkg_name):
    global debian_fails, debian_successes

    if pkg_name not in data:
        debian_fails += 1
        return []
    debian_successes += 1
    pkg_data = data[pkg_name]
    return [cve_id for cve_id, _ in pkg_data.items()]

def debian_method(installs, cve_desc_map):
    tracker = get_debian_tracker()

    for pkg in installs:
        raw = get_debian_cves(tracker, pkg['name'])
        pkg['cves'] = raw

        details = []
        for cve in raw:
            desc = cve_desc_map.get(cve)
            if desc:
                details.append({"id": cve, "description": desc})
        pkg['cve_details'] = details

    with open('results.json', 'w', encoding='utf-8') as f:
        json.dump(installs, f, indent=2)

    print(f"Number of successful matches in Debian: {debian_successes}")
    print(f"Number of failed matches in Debian:   {debian_fails}")

def get_installs(ip, username='msfadmin', password='msfadmin'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)

    stdin, stdout, stderr = ssh.exec_command('dpkg -l')
    output = stdout.read().decode('utf-8')
    ssh.close()

    with open('installed.txt', 'w', encoding='utf-8') as f:
        f.write(output)

    return output

def parse_installs(installs):
    pkgs = []
    for line in installs.splitlines():
        if line.startswith('ii'):
            parts = line.split()
            pkgs.append({
                'name': parts[1],
                'version': parts[2],
                'description': ' '.join(parts[3:]),
                'cves': None
            })
    return pkgs

def main():
    # read the target VM IP
    with open('ip.txt', 'r') as f:
        ip = f.read().strip()

    # pull the list of installed packages
    get_installs(ip)
    with open('installed.txt', 'r') as f:
        dpkg_output = f.read()
    installs = parse_installs(dpkg_output)

    # load the full NVD 2.0 “recent” feed (gzipped JSON)
    nvd_url = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz"
    cve_desc_map = load_nvd_feed(nvd_url)

    # run the Debian‑tracker + description annotation
    debian_method(installs, cve_desc_map)

if __name__ == '__main__':
    main()
