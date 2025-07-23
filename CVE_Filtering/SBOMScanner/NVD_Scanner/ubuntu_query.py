import json
import re
import time
from packaging import version

def simplify_version(version):
    return re.split(r'[-+~]', version)[0]

def parse_installed_packages(file_path='installed.txt'):
    packages = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[1].lower()
                    ver = parts[2].strip()
                    packages.append({'name': name, 'version': ver, 'cves': []})
    return packages


def load_ubuntu_cves(json_path='ubuntu_cves.json'):
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)




def extract_affected_from_description(desc):
    """
    Extracts affected packages and their versions from the CVE description.
    Returns a list of (package, version) tuples.
    """
    matches = re.findall(r'^(\S+)\s+-\s+([\w\d\.\-\:\+~]+)', desc, re.MULTILINE)
    return [(pkg.lower(), simplify_version(ver)) for pkg, ver in matches]


def match_cves(packages, cve_entries):
    matched = []

    for pkg in packages:
        for cve in cve_entries:
            desc = cve.get("description", "").lower()

            if "do not use this candidate number" in desc or "rejected" in desc:
                continue

            affected_list = extract_affected_from_description(desc)

            for name, ver in affected_list:
                if pkg['name'] == name:
                    try:
                        if version.parse(pkg['version']) < version.parse(ver):
                            cve_info = {
                                'cve_id': cve.get('CVE'),
                                'affected_pkg': name,
                                'affected_version': ver,
                                'title': cve.get('title', ''),
                                'description': cve.get('description', '')
                            }
                            pkg['cves'].append(cve_info)
                            matched.append(cve_info)
                    except Exception:
                        continue
    return matched



def main():
    start = time.time()

    print("Parsing installed packages...")
    packages = parse_installed_packages()
    print(f"Parsed {len(packages)} packages.")

    print("Loading Ubuntu CVE JSON...")
    cve_data = load_ubuntu_cves()
    print(f"Loaded {len(cve_data)} CVE entries.")

    print("Matching packages with CVEs...")
    matches = match_cves(packages, cve_data)

    print(f"Found (matches) CVE matches.")

    

    # Print summary
    vuln_count = 0
    vulnerable_pkgs = []
    unmatched_pkgs = 0

    for pkg in packages:
        cves = pkg.get('cves', [])
        if isinstance(cves, list) and cves:
            vuln_count += len(cves)
            vulnerable_pkgs.append(pkg)
    else:
        unmatched_pkgs += 1



    print(f"Found {len(matches)} CVE matches.")

    # CVE summary
    vuln_count = 0
    vulnerable_pkgs = []
    unmatched_pkgs = 0

    for pkg in packages:
        cves = pkg.get('cves', [])
        if isinstance(cves, list) and cves:
            vuln_count += len(cves)
            vulnerable_pkgs.append(pkg)
        else:
          unmatched_pkgs += 1

    print(f"\n Found {vuln_count} total CVE vulnerabilities affecting {len(vulnerable_pkgs)} packages.\n")
    print(f" {unmatched_pkgs} packages had no matching vulnerabilities.\n")


    # Save output
    with open('matched_packages.json', 'w', encoding='utf-8') as f:
        json.dump([p for p in packages if p['cves']], f, indent=2)

    with open('all_packages_cves.json', 'w', encoding='utf-8') as f:
        json.dump(packages, f, indent=2)

    print(f"Execution time: {time.time() - start:.2f} seconds.")


if __name__ == '__main__':
    main()
