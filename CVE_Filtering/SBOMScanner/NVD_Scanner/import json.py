import json
import re
import time
from packaging import version


def simplify_version(v):
    """Strip distro suffixes like -ubuntu1, +dfsg1, etc."""
    return re.split(r'[-+~]', v)[0]


def parse_installed_packages(file_path='installed.txt'):
    packages = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('ii'):
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[1].lower()
                    ver = simplify_version(parts[2])
                    packages.append({'name': name, 'version': ver, 'cves': []})
    return packages


def load_ubuntu_cves(json_path='ubuntu_cves.json'):
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def is_pkg_affected(pkg_name, pkg_version, affected_entry):
    affected_entry = affected_entry.lower()
    pkg_name = pkg_name.lower()

    if pkg_name in affected_entry and "is earlier than" in affected_entry:
        # Extract version after 'is earlier than'
        try:
            affected_version = affected_entry.split("is earlier than")[1].strip().split()[0]
            affected_version = simplify_version(affected_version)
            return version.parse(pkg_version) < version.parse(affected_version)
        except Exception as e:
            print(f"[ERROR] Version comparison failed: {e}")
            return False
    return False



def match_cves(packages, cve_entries):
    matched = []

    for pkg in packages:
        for cve in cve_entries:
            for affected in cve.get("affected", []):
                if is_pkg_affected(pkg['name'], pkg['version'], affected):
                    pkg['cves'].append({
                        'cve_id': cve.get('cve_id'),
                        'title': cve.get('title', ''),
                        'description': cve.get('description', ''),
                        'affected': affected
                    })
                    matched.append((pkg['name'], cve.get('cve_id')))
                    break  # Avoid duplicate CVEs per package
    return matched


def main():
    start = time.time()

    print("[INFO] Parsing installed packages...")
    packages = parse_installed_packages()
    print(f"[INFO] Parsed {len(packages)} packages.")

    print("[INFO] Loading Ubuntu CVE JSON...")
    cve_data = load_ubuntu_cves()
    print(f"[INFO] Loaded {len(cve_data)} CVE entries.")

    print("[INFO] Matching packages with CVEs...")
    matches = match_cves(packages, cve_data)

    print(f"[RESULT] Found {len(matches)} CVE matches.")

    # Print summary for each matched package
    for pkg in packages:
        if pkg['cves']:
            print(f"\nPackage: {pkg['name']} ({pkg['version']})")
            for cve in pkg['cves']:
                print(f" - CVE: {cve['cve_id']}")
                print(f"   Affected: {cve['affected']}")
                print(f"   Title: {cve['title']}")
                print(f"   Desc: {cve['description'][:100]}...")

    # Save results
    with open('matched_packages.json', 'w', encoding='utf-8') as f:
        json.dump([p for p in packages if p['cves']], f, indent=2)

    with open('all_packages_cves.json', 'w', encoding='utf-8') as f:
        json.dump(packages, f, indent=2)

    print(f"[DONE] Execution time: {time.time() - start:.2f} seconds.")


if __name__ == '__main__':
    main()
