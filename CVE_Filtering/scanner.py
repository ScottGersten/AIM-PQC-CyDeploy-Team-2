import platform
import socket
import subprocess
import requests
import json
import os
import threading
import random
import time
from urllib.parse import urlparse
import ipaddress
import psutil

# Optional: Define multiple target directories to scan
TARGET_PATHS = ["192.168.1.0"]

def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine()
    }

def build_cmdb():
    cmdb = {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "software": get_installed_software(),
        "network": get_network_info(),
        "dependencies": []
    }
    return cmdb

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

def get_network_info():
    info = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                info.append({"interface": interface, "ip": addr.address})
    return info

def save_cmdb(cmdb, filename="cmdb.json"):
    with open(filename, "w") as f:
        json.dump(cmdb, f, indent=2)

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

def scan_subnet(subnet, results_dict):
    print(f"\nScanning subnet: {subnet}")
    net = ipaddress.IPv4Network(subnet, strict=False)
    live_hosts = []

    for ip in net.hosts():
        ip = str(ip)
        try:
            result = subprocess.run(["ping", "-n", "1", "-w", "200", ip],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if "TTL=" in result.stdout:
                print(f"Host up: {ip}")
                live_hosts.append(ip)
                scan_ip_address(ip, results_dict)
            else:
                print(f"No response: {ip}")
        except Exception as e:
            print(f"Error pinging {ip}: {e}")

    if not live_hosts:
        print("No live hosts detected.")

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
        print("STDOUT:", result.stdout)
        return False
    else:
        print(f"Scan successful for {scan_dir}")
        print("STDOUT:", result.stdout)
        return True

def read_scan_output(output_file):
    if os.path.exists(output_file):
        with open(output_file) as f:
            return json.load(f)
    return []

def scan_ip_address(ip, results_dict):
    print(f"Scanning services on IP: {ip}")
    result = subprocess.run(["nmap", "-sV", ip], capture_output=True, text=True)
    print(result.stdout)
    results_dict[ip] = {"nmap_output": result.stdout}

def scan_url(url, results_dict):
    print(f"Connecting to URL: {url}")
    try:
        response = requests.get(url, timeout=5)
        server = response.headers.get("Server", "Unknown")
        print(f"Server header: {server}")
        results_dict[url] = {
            "status_code": response.status_code,
            "server": server
        }
    except Exception as e:
        print(f"Could not reach {url}: {e}")
        results_dict[url] = {"error": str(e)}

def send_results_to_server(payload, server_url):
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(server_url, data=json.dumps(payload), headers=headers)
        print(f"Server response: HTTP {response.status_code}")
        return response.status_code
    except Exception as e:
        print(f"Failed to send data to server: {e}")
        return None

def threaded_scan(target, results_dict):
    target_type = detect_target_type(target)

    if target_type == "file":
        safe_path = target.replace(':', '').replace('\\', '_').replace('/', '_')
        output_file = f"{safe_path}_cve.json"

        if run_cve_scan(target, output_file):
            findings = read_scan_output(output_file)
            results_dict[target] = findings

            if findings:
                print(f"\nVulnerabilities found in {target}:")
                for item in findings:
                    print(f"  File: {item['file']}")
                    print(f"  Product: {item['product']}")
                    print(f"  Version: {item['version']}")
                    print(f"  CVEs: {', '.join(item['cves'])}")
                    print("  ---")

                all_cves = []
                for item in findings:
                    all_cves.extend(item["cves"])

                if all_cves:
                    system_info = get_system_info()
                    quantum_walk_simulate(all_cves, system_info)

            else:
                print(f"No known vulnerabilities found in {target}")

    elif target_type == "ip":
        scan_ip_address(target, results_dict)

    elif target_type == "url":
        scan_url(target, results_dict)

    elif target_type == "subnet":
        scan_subnet(target, results_dict)

    else:
        print(f"Unknown target type: {target}")
        results_dict[target] = {"error": "Unrecognized target format"}

def quantum_walk_simulate(cve_list, system_info, steps=5):
    print("\nSimulating Quantum Walk through CVEs...")
    if not cve_list:
        print("No CVEs to walk through.")
        return None

    amplitudes = {cve: 1 / len(cve_list) for cve in cve_list}

    for step in range(steps):
        print(f"\nStep {step + 1}")
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
            print(f"  {i+1}. {cve} (amplitude ≈ {amp:.4f})")

    most_likely_cve = max(amplitudes, key=amplitudes.get)
    print(f"\nMost likely vulnerable CVE found: {most_likely_cve}")
    return most_likely_cve

def grover_simulate(cve_list, target_cve, cmdb):
    print(f"\nSimulating Grover's Search for: {target_cve}")
    if not cve_list:
        print("No CVEs to search.")
        return None

    filtered_list = [
        cve for cve in cve_list
        if matches_environment(cve, cmdb)
    ]

    if not filtered_list:
        print("No CVEs matched the current environment.")
        return None

    iterations = int(len(filtered_list) ** 0.5) or 1
    print(f"Estimated iterations: {iterations}")

    for i in range(iterations):
        guess = random.choice(filtered_list)
        print(f"Try {i+1}: {guess}")
        if guess == target_cve:
            print(f"Found vulnerable CVE: {guess}")
            return guess

    print("Target CVE not found.")
    return None

def matches_environment(cve, cmdb):
    cve_text = cve.lower()
    return (
        cmdb["os"].lower() in cve_text or
        cmdb["architecture"].lower() in cve_text or
        any(software.lower() in cve_text for software in cmdb.get("software", []))
    )

def agent_main():
    print("Agent starting...")

    cmdb = build_cmdb()
    save_cmdb(cmdb)
    results_dict = {}

    threads = []
    for target in TARGET_PATHS:
        t = threading.Thread(target=threaded_scan, args=(target, results_dict))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    all_cves = []
    for result in results_dict.values():
        if isinstance(result, list):
            for entry in result:
                all_cves.extend(entry.get("cves", []))

    if all_cves:
        target_cve = all_cves[0]
        grover_simulate(all_cves, target_cve, cmdb)

    with open("scan_results.json", "w") as f:
        json.dump(results_dict, f, indent=2)
    print("Scan results saved.")

if __name__ == "__main__":
    s_time = time.time()
    agent_main()
    e_time = time.time()
    c_time = e_time - s_time
    print(f"{c_time:.2f} seconds")
