import paramiko
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

debian_fails = 0
debian_successes = 0

def fetch_cve_descriptions_circl_parallel(cve_list, max_workers=20):

    base = "https://cve.circl.lu/api/cve/"

    def lookup(cve):
        try:
            r = requests.get(base + cve, timeout=3)
            r.raise_for_status()
            data = r.json()

            # 1) top‐level summary?
            desc = data.get("summary")

            # 2) nested English descriptions?
            if not desc:
                for d in (
                    data
                    .get("containers", {})
                    .get("cna", {})
                    .get("descriptions", [])
                ):
                    if d.get("lang") == "en":
                        desc = d.get("value")
                        break

            return {"id": cve, "description": desc}
        except Exception:
            return {"id": cve, "description": None}

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(lookup, cve): cve for cve in cve_list}
        for fut in as_completed(futures):
            results.append(fut.result())

    return results


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

    # pkg_data is a dict { "CVE‑ID": {...}, ... }
    return list(pkg_data.keys())


def debian_method(installs):
    data = get_debian_tracker()

    # for each package, attach .cves and .cve_details
    for pkg in installs:
        raw = get_debian_cves(data, pkg["name"])
        pkg["cves"] = raw or []

        if raw:
            details = fetch_cve_descriptions_circl_parallel(raw)
            # drop any with no description
            pkg["cve_details"] = [d for d in details if d["description"]]
        else:
            pkg["cve_details"] = []

    # collect a flat list of every described CVE
    all_described = []
    for pkg in installs:
        all_described.extend(pkg["cve_details"])

    # write everything into a single JSON
    # output = {
    #     "described_cves": all_described,
    #     "packages": installs
    # }
    output = {
        "packages": installs,
        "described_cves": all_described
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

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
                # these get filled in debian_method
                "cves": [],
                "cve_details": []
            })
    return packages


def main():
    start_time = time.time()

    with open("ip.txt", "r") as f:
        ip = f.read().strip()

    # fetch & parse
    #get_installs(ip)
    with open("installed.txt", "r") as f:
        text = f.read()
    installs = parse_installs(text)

    # run Debian CVE‐lookup + description pull
    debian_method(installs)

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")


if __name__ == "__main__":
    main()
