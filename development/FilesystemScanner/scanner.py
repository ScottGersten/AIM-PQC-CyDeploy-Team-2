import platform
import socket
import subprocess
import requests
import json
import os
import threading
import random
import time

# Optional: Define multiple target directories to scan
TARGET_PATHS = [r"C:\Users\baseb\OneDrive\Documents\metasploitable_root\usr\bin"]

s_time = time.time()

def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine()
    }

def run_cve_scan(scan_dir, output_file):
    print(f"Scanning {scan_dir}...")
    
    # Verify directory exists
    if not os.path.exists(scan_dir):
        print(f"Directory not found: {scan_dir}")
        return False

    # Command to run cve-bin-tool
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
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)

                # If the result is a list, return it directly
                if isinstance(data, list):
                    return data

                # If it's a dict, extract matches
                found = []
                for entry in data.get("matches", []):
                    if "cve" in entry:
                        found.append({
                            "file": entry.get("file", "unknown"),
                            "product": entry.get("product", "unknown"),
                            "version": entry.get("version", "unknown"),
                            "cves": entry.get("cve", []),
                        })
                return found
        except Exception as e:
            print(f"Error reading scan output: {e}")
    return []


def threaded_scan(path, results_dict):
    safe_path = path.replace(':', '').replace('\\', '_').replace('/', '_')
    output_file = f"{safe_path}_cve.json"
    if run_cve_scan(path, output_file):
        results_dict[path] = read_scan_output(output_file)

def grover_simulate(cve_list, target_cve):
    print(f"\n Simulating Grover's Search for: {target_cve}")
    
    if not cve_list:
        print("No CVEs found to search through.")
        return None

    iterations = int(len(cve_list) ** 0.5) or 1
    print(f"Estimated iterations: {iterations}")
    
    for i in range(iterations):
        guess = random.choice(cve_list)
        print(f"  Try {i+1}: {guess}")
        if guess == target_cve:
            print(f"Found vulnerable CVE: {guess}")
            return guess

    print("Target CVE not found.")
    return None

def agent_main():
    print("Agent starting scan...\n")

    info = get_system_info()
    results_dict = {}

    threads = []
    for path in TARGET_PATHS:
        t = threading.Thread(target=threaded_scan, args=(path, results_dict))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n All scans completed.\n")

    payload = {
        "system_info": info,
        "cve_scan_results": results_dict
    }

    # Replace with your actual API endpoint
    
    with open("scan_results.json", "w") as f:
        json.dump(payload, f, indent=2)
    print(" Results written to local file.")

e_time = time.time()

c_time = e_time - s_time

if __name__ == "__main__":
    agent_main()

print (c_time)
