import winreg
import json
import paramiko
import re
import csv
from packaging.version import parse as parse_version


def get_installed_software_windows():
    #Retrieve installed software locally via Windows registry.
    software = []
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
    ]

    for hive, path in registry_paths:
        try:
            with winreg.OpenKey(hive, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    subkey_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, subkey_name) as subkey:
                        try:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            software.append({"name": name, "version": version})
                        except FileNotFoundError:
                            continue
                        except OSError:
                            continue
        except FileNotFoundError:
            continue

    return software


def get_installs_remote(ip, username='sshuser', password='YourStrongPassword123!'):
    
    #Retrieve installed software remotely over SSH from a Windows host.
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)

    cmd = (
        "powershell -Command \""
        "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
        "| Select-Object DisplayName, DisplayVersion\""
    )
    
    stdin, stdout, stderr = ssh.exec_command(cmd)
    output = stdout.read().decode('utf-8')
    ssh.close()

    with open('windows_installed.txt', 'w', encoding='utf-8') as file:
        file.write(output)


def load_nvd_cves(path='all_cves.json'):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("CVE_Items", [])


def load_msrc_csv(path="MSRC.csv"):
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)


def clean_name(name):
    """Removes all characters that are not lowercase letters or digits."""
    return re.sub(r'[^a-z0-9]', '', name.lower())


def match_software_to_cves(software_list, cve_data):
    matched = []
    for sw in software_list:
        sw_name = clean_name(sw["name"])
        sw_version = sw["version"]

        try:
            sw_parsed = parse_version(sw_version)
        except Exception:
            continue

        for item in cve_data:
            if not isinstance(item, dict) or "cve" not in item:
                continue
            try:
                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                descs = item["cve"]["description"]["description_data"]
                description = " ".join(d["value"] for d in descs).lower()
                cleaned_description = clean_name(description)

                if sw_name in cleaned_description:
                    # Sees if the version is before the vulnerable version.
                    version_match = re.search(r"before\s+(\d+(?:\.\d+)+)", description)
                    if version_match:
                        vuln_version = parse_version(version_match.group(1))
                        if sw_parsed < vuln_version:
                            matched.append({
                                "software": sw["name"],
                                "installed_version": sw["version"],
                                "cve_id": cve_id,
                                "description": description,
                                "source": "nvd"
                            })
                    else:
                        matched.append({
                            "software": sw["name"],
                            "installed_version": sw["version"],
                            "cve_id": cve_id,
                            "description": description,
                            "source": "nvd"
                        })
            except Exception:
                continue
    return matched


def match_software_to_msrc(software_list, msrc_data):
    matched = []
    seen = set()

    for sw in software_list:
        sw_name = sw["name"].lower()
        sw_version = sw["version"]

        for row in msrc_data:
            product = row.get("Product", "").lower()
            vuln_cve = row.get("CVE ID")
            title = row.get("Vulnerability Title", "")

            if sw_name in product and vuln_cve not in seen:
                matched.append({
                    "software": sw["name"],
                    "installed_version": sw_version,
                    "cve_id": vuln_cve,
                    "title": title,
                    "source": "msrc"
                })
                seen.add(vuln_cve)
    return matched


def save_results(results, output_path='windows_vulns.json'):
    if results:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(f"Saved {len(results)} results to {output_path}")
    else:
        print("No vulnerabilities found. Nothing saved.")


def main():
    
    print("Collecting installed software locally...")
    software = get_installed_software_windows()
    print(f"{len(software)} programs detected.")

    
    print("Loading CVE data from NVD...")
    cves = load_nvd_cves('all_cves.json')
    print(f"{len(cves)} NVD CVEs loaded.")

    print("Loading MSRC CSV data...")
    msrc_data = load_msrc_csv()
    print(f"{len(msrc_data)} MSRC CVEs loaded.")

    
    print("Matching software to NVD CVEs...")
    nvd_matches = match_software_to_cves(software, cves)
    print(f"{len(nvd_matches)} NVD vulnerabilities found.")

    print("Matching software to MSRC CSV...")
    msrc_matches = match_software_to_msrc(software, msrc_data)
    print(f"{len(msrc_matches)} MSRC vulnerabilities found.")

    
    all_matches = nvd_matches + msrc_matches
    save_results(all_matches)


if __name__ == "__main__":
    main()
