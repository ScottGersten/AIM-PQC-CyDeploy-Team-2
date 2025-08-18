import platform
import socket
import subprocess
import requests
import json
import os
import random
import time
import ipaddress
from urllib.parse import urlparse
from multiprocessing import Pool, cpu_count

# === Configuration ===
TARGET_PATHS = [r"C:\Users\kklov\Downloads\meta\usr\lib"]

# === Utility Functions ===
def detect_target_type(target):
    if os.path.exists(target):
        return "file"
    elif target.startswith("http://") or target.startswith("https://"):
        return "url"
    try:
        ipaddress.IPv4Address(target)
        return "ip"
    except ValueError:
        pass
    try:
        ipaddress.IPv4Network(target)
        return "subnet"
    except ValueError:
        pass
    return "unknown"

def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine()
    }

def build_cmdb():
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "software": get_installed_software(),
        "network": get_network_info_basic(),
        "dependencies": []
    }

def get_installed_software():
    software = []
    try:
        if platform.system() == "Windows":
            import winreg
            reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            for i in range(0, winreg.QueryInfoKey(hkey)[0]):
                subkey_name = winreg.EnumKey(hkey, i)
                subkey = winreg.OpenKey(hkey, subkey_name)
                try:
                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                    software.append(name)
                except FileNotFoundError:
                    continue
        else:
            result = subprocess.run(["dpkg-query", "-W", "-f=${binary:Package}\n"],
                                    capture_output=True, text=True)
            software = result.stdout.splitlines()
    except Exception as e:
        software.append(f"Error: {e}")
    return software

def get_network_info_basic():
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "Unknown"
    return [{"interface": "main", "ip": ip}]

def save_cmdb(cmdb, filename="cmdb.json"):
    with open(filename, "w") as f:
        json.dump(cmdb, f, indent=2)

def run_cve_scan(scan_dir, output_file):
    print(f"Scanning {scan_dir}...")
    if not os.path.exists(scan_dir):
        print(f"Directory not found: {scan_dir}")
        return False

    cmd = ["cve-bin-tool", scan_dir, "-f", "json", "-o", output_file]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Scan failed for {scan_dir}")
        print("STDERR:", result.stderr)
        return False
    else:
        print(f"Scan successful for {scan_dir}")
        return True

def read_scan_output(output_file):
    if os.path.exists(output_file):
        with open(output_file) as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: {output_file} could not be parsed as JSON.")
                return []
    return []

def is_executable(file_path):
    return file_path.lower().endswith(('.exe', '.dll', '.bin', '.so'))

def collect_executables(scan_dir):
    executable_files = []
    for root, dirs, files in os.walk(scan_dir):
        for file in files:
            full_path = os.path.join(root, file)
            if is_executable(full_path):
                executable_files.append(full_path)
    return executable_files

def matches_environment(cve, cmdb):
    cve_text = cve.lower()
    return (
        cmdb["os"].lower() in cve_text or
        cmdb["architecture"].lower() in cve_text or
        any(software.lower() in cve_text for software in cmdb.get("software", []))
    )

# === Quantum-Inspired Algorithms ===
def quantum_walk_simulate(cve_list, system_info, steps=5):
    print("\nSimulating Quantum Walk through CVEs...")
    if not cve_list:
        return None
    amplitudes = {cve: 1 / len(cve_list) for cve in cve_list}
    for step in range(steps):
        new_amplitudes = {}
        for cve in cve_list:
            match_score = 1
            if matches_environment(cve, system_info):
                match_score += 2
            for neighbor in cve_list:
                if neighbor not in new_amplitudes:
                    new_amplitudes[neighbor] = 0
                new_amplitudes[neighbor] += amplitudes[cve] * match_score / len(cve_list)
        total = sum(new_amplitudes.values())
        amplitudes = {k: v / total for k, v in new_amplitudes.items()}
        top = sorted(amplitudes.items(), key=lambda x: x[1], reverse=True)[:3]
        for i, (cve, amp) in enumerate(top):
            print(f"{i+1}. {cve} (amplitude ≈ {amp:.4f})")
    most_likely_cve = max(amplitudes, key=amplitudes.get)
    print(f"Most likely CVE: {most_likely_cve}")
    return most_likely_cve

def grover_simulate(cve_list, target_cve, cmdb):
    print(f"\nSimulating Grover's Search for: {target_cve}")
    if not cve_list:
        return None
    filtered_list = [cve for cve in cve_list if matches_environment(cve, cmdb)]
    if not filtered_list:
        print("No matching CVEs found.")
        return None
    iterations = int(len(filtered_list) ** 0.5) or 1
    for i in range(iterations):
        guess = random.choice(filtered_list)
        print(f"Try {i+1}: {guess}")
        if guess == target_cve:
            print(f"Found CVE: {guess}")
            return guess
    print("Target CVE not found.")
    return None

# === Scanning Functions ===
def threaded_scan(target, results_dict):
    target_type = detect_target_type(target)
    safe_path = target.replace(':', '').replace('\\', '_').replace('/', '_')
    output_file = f"{safe_path}_cve.json"

    if target_type == "file":
        if run_cve_scan(target, output_file):
            findings = read_scan_output(output_file)
            results_dict[target] = findings

            if findings:
                print(f"\n[VULNERABILITIES FOUND] in {target}:")
                for item in findings:
                    print(f"- File: {item.get('file', 'unknown')}")
                    print(f"  Product: {item.get('product', 'N/A')}")
                    print(f"  Version: {item.get('version', 'N/A')}")
                    print(f"  CVEs: {', '.join(item.get('cves', []))}")
                    print("---")

                all_cves = [cve for item in findings for cve in item.get("cves", [])]
                if all_cves:
                    system_info = get_system_info()
                    quantum_walk_simulate(all_cves, system_info)
            else:
                print(f"No vulnerabilities found in {target}")

    else:
        print(f"Skipping non-file target: {target}")

def scan_target_wrapper(target):
    result = {}
    threaded_scan(target, result)
    return result

# === Main Execution ===
def agent_main():
    print("Agent starting...")
    cmdb = build_cmdb()
    save_cmdb(cmdb)

    # Collect executables from defined paths
    all_targets = []
    for path in TARGET_PATHS:
        all_targets.extend(collect_executables(path))

    print(f"\nCollected {len(all_targets)} executables to scan.\n")

    # Run multiprocessing scan
    with Pool(processes=cpu_count()) as pool:
        results_list = pool.map(scan_target_wrapper, all_targets)

    # Merge results
    final_results = {}
    for partial in results_list:
        final_results.update(partial)

    # Run Grover Simulation
    all_cves = [cve for result in final_results.values()
                for entry in (result if isinstance(result, list) else [])
                for cve in entry.get("cves", [])]
    if all_cves:
        target_cve = all_cves[0]
        grover_simulate(all_cves, target_cve, cmdb)

    with open("scan_results.json", "w") as f:
        json.dump(final_results, f, indent=2)
    print("Scan results saved.")

if __name__ == "__main__":
    start = time.time()
    agent_main()
    end = time.time()
    print(f"Total scan time: {end - start:.2f} seconds")