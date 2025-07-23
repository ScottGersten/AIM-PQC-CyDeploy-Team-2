import paramiko
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def fetch_cve_descriptions(cves, max_threads=200):
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
    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        futures = {ex.submit(lookup, cve): cve for cve in cves}
        for fut in as_completed(futures):
            results.append(fut.result())

    return results

def get_vulnerabilities(installs):
    for pkg in installs:
        if pkg['cves']:
            details = fetch_cve_descriptions(pkg['cves'])
            pkg["cve_details"] = [d for d in details if d["description"]]
        else:
            pkg['cve_details'] = None

    with open('vulnerabilities.json', 'w', encoding='utf-8') as file:
        json.dump(installs, file, indent=2)

def main():
    start_time = time.time()

    with open('results.json', 'r', encoding='utf-8') as file:
        installs = json.load(file)
    #print(installs[0:2])

    get_vulnerabilities(installs[0:10])
    
    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")

if __name__ == '__main__':
    main()