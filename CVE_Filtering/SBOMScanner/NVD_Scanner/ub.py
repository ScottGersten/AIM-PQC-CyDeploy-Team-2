import json
import re
import time
from packaging import version
from concurrent.futures import ThreadPoolExecutor, as_completed

def simplify_version(version_str):
    return re.split(r'[-+~]', version_str)[0]

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

def extract_fixed_versions(description):
    # Matches lines like: xterm - 353-1ubuntu1.20.04.2
    pattern = r'^(\S+)\s+-\s+([\w\d\.\-~\+:]+)'
    return re.findall(pattern, description, re.MULTILINE)

def match_single_package(pkg, cve_entries):
    pkg_name = pkg['name']
    pkg_ver = pkg['version']
    found = []

    for cve in cve_entries:
        desc = cve.get("description", "").lower()
        if "do not use this candidate number" in desc or "rejected" in desc:
            continue

        fixed_versions = extract_fixed_versions(desc)
        for affected_name, fixed_ver in fixed_versions:
            if affected_name.lower() == pkg_name:
                try:
                    if version.parse(pkg_ver) < version.parse(fixed_ver):
                        cve_info = {
                            'cve_id': cve.get('CVE'),
                            'affected_pkg': affected_name,
                            'affected_version': fixed_ver,
                            'title': cve.get('title', ''),
                            'description': cve.get('description', '')
                        }
                        found.append(cve_info)
                except Exception:
                    continue
    pkg['cves'] = found
    return pkg

def match_cves_threaded(packages, cve_entries, max_threads=10):
    matched = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_pkg = {executor.submit(match_single_package, pkg, cve_entries): pkg for pkg in packages}
        for future in as_completed(future_to_pkg):
            result = future.result()
            if result['cves']:
                matched.extend(result['cves'])
    return packages, matched

def main():
    start = time.time()

    print("Parsing installed packages...")
    packages = parse_installed_packages()
    print(f"Parsed {len(packages)} packages.")

    print("Loading Ubuntu CVE JSON...")
    cve_data = load_ubuntu_cves()
    print(f"Loaded {len(cve_data)} CVE entries.")

    print("Matching packages with CVEs using threading...")
    packages, matches = match_cves_threaded(packages, cve_data, max_threads=20)

    # Summary
    vuln_count = sum(len(pkg['cves']) for pkg in packages if pkg['cves'])
    vulnerable_pkgs = [pkg for pkg in packages if pkg['cves']]
    unmatched_pkgs = len([pkg for pkg in packages if not pkg['cves']])

    print(f"\n✅ Found {vuln_count} total CVE vulnerabilities affecting {len(vulnerable_pkgs)} packages.")
    print(f"❌ {unmatched_pkgs} packages had no matching vulnerabilities.\n")

    # Save results
    with open('matched_packages.json', 'w', encoding='utf-8') as f:
        json.dump(vulnerable_pkgs, f, indent=2)

    with open('all_packages_cves.json', 'w', encoding='utf-8') as f:
        json.dump(packages, f, indent=2)

    print(f"⏱️ Execution time: {time.time() - start:.2f} seconds.")

if __name__ == '__main__':
    main()
