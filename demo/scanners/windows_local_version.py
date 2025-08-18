import paramiko
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime
import re
import threading

found_cve_ids = 0

COMMON_PREFIXES = [
    'lib', 'python-', 'perl-', 'golang-', 'nodejs-', 
    'ms-', 'microsoft-', 'windows-', 'win-', 'vc-', 'vs-', 'vcredist-', 'dotnet-', 
    'adobe-', 'oracle-', 'java-', 'jdk-', 'jre-', 'openjdk-', 
    'msvc-', 'msxml-', 'msedge-', 'chromium-', 'chrome-', 'mozilla-', 'firefox-', 
    'sqlserver-', 'postgresql-', 'mysql-', 'mariadb-', 
    'vmware-', 'virtualbox-', 'cygwin-', 'mingw-'
]

def strip_prefix(name):
    for prefix in COMMON_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name

def strip_trailing_version_suffix(name):
    return re.sub(r'\d+(off)?$', '', name)

def normalize_name(name):
    name = name.lower()
    name = name.replace('-', '')
    name = name.replace('_', '')
    name = strip_prefix(name)
    name = strip_trailing_version_suffix(name)
    return name

def match_cves(installs, data):
    global found_cve_ids

    INVALID_CVE = 'Rejected reason: DO NOT USE THIS CANDIDATE NUMBER.'
    INVALID_CVE_2 = 'rejected reason:'

    vulns = []
    seen_cves = set()

    for pkg in installs:
        name = pkg['name']
        norm_name = pkg['norm_name']
        first_year = pkg['first_year']
        last_year = pkg['last_year']
        # if first_year is None or last_year is None:
        #     continue
        if first_year is None:
            first_year = 2025
        
        for year in range(first_year, last_year + 1):
            year_str = str(year)
            if year_str not in data:
                continue
            for item in data[year_str]:
                cve_id = item.get('id')
                description = item.get('description', '')
                raw = item.get('raw', {})
                impact = raw.get('impact', {})
                base_metric = impact.get('baseMetricV3', {})
                # if base_metric == {}:
                #     base_metric = impact.get('baseMetricV2', {})
                exploitability_score = base_metric.get('exploitabilityScore', None)
                impact_score = base_metric.get('impactScore', None)
                cvss = base_metric.get('cvssV3', {})
                attack_vector = cvss.get('attackVector', None)
                attack_complexity = cvss.get('attackComplexity', None)
                privileges_required = cvss.get('privilegesRequired', None)
                user_interaction = cvss.get('userInteraction', None)
                scope = cvss.get('scope', None)
                confidentiality_impact = cvss.get('confidentialityImpact', None)
                integrity_impact = cvss.get('integrityImpact', None)
                availability_impact = cvss.get('availabilityImpact', None)
                #if name.lower() in description.lower():
                #if INVALID_CVE not in description and normalize_name(name) in normalize_name(description):
                #if INVALID_CVE not in description and norm_name in normalize_name(description):
                #if INVALID_CVE not in description and name.lower() in description.lower():
                if INVALID_CVE not in description and INVALID_CVE_2 not in description and name.lower() in description.lower():
                    cve_info = {
                                'id': cve_id, 
                                'desc': description, 
                                #'exploitability_score': exploitability_score, 
                                #'impact_score': impact_score,
                                'attack_vector': attack_vector,
                                'attack_complexity': attack_complexity,
                                'privileges_required': privileges_required,
                                'user_interaction': user_interaction,
                                'scope': scope,
                                'confidentiality_impact': confidentiality_impact,
                                'integrity_impact': integrity_impact,
                                'availability_impact': availability_impact
                                }
                    #pkg['cves'].append(cve_id)
                    pkg['cves'].append({'id': cve_id, 'desc': description})
                    #found_cve_ids += 1
                    if cve_id not in seen_cves:
                        #vulns.append({'id': cve_id, 'desc': description})
                        vulns.append(cve_info)
                        seen_cves.add(cve_id)
                        found_cve_ids += 1
    
    return vulns

def get_installs(ip, username='msfadmin', password='msfadmin'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(ip, username=username, password=password)

    cmd = r'''powershell -Command "Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Json"'''

    stdin, stdout, stderr = ssh.exec_command(cmd)
    output = stdout.read().decode('utf-8')

    #print(f"Error: {stderr.read().decode()}")
    softwares = json.loads(output)

    packages = []
    for item in softwares:
        name = item.get('DisplayName')
        version = item.get('DisplayVersion')
        #first_year, last_year = 0, 0 #get_package_years(ssh, name)
        install_date = item.get('InstallDate')
        install_year = datetime.strptime(install_date, "%Y%m%d").year if install_date is not None else None
        packages.append({
            'type': 'installed',
            'name': name,
            'norm_name' : normalize_name(name),
            'version': version,
            'first_year': install_year,
            'last_year': 2025,
            'cves': []
        })

    cmd = r'''powershell -Command "Get-Service | Where-Object { $_.Status -eq 'Running' } | ConvertTo-Json"'''
    stdin, stdout, stderr = ssh.exec_command(cmd)
    output = stdout.read().decode('utf-8')
    running = json.loads(output)

    for item in running:
        name = item.get('ServiceName')
        packages.append({
            'type': 'running',
            'name': name,
            'norm_name': normalize_name(name),
            'version': None,
            'first_year': None,
            'last_year': 2025,
            'cves': []
        })
    
    with open('installed_windows.json', 'w', encoding='utf-8') as file:
        json.dump(packages, file, indent=2)

    # running_softwares = []
    # for item in running:
    #     name = item.get('ServiceName')
    #     running_softwares.append({
    #         'name': name,
    #         'norm_name': normalize_name(name)
    #     })
    
    # with open('running_windows.json', 'w', encoding='utf-8') as file:
    #     json.dump(running_softwares, file, indent=2)

    ssh.close()
    return packages

def run_windows_local():
    start_time = time.time()

    filename = 'ssh_windows_local.txt'
    #filename = 'ssh_windows_vm.txt'
    
    with open(filename, 'r') as f:
        lines = f.read().splitlines()
        ip = lines[0]
        username = lines[1]
        password = lines[2]

    installs = get_installs(ip, username, password)
    # with open('installed_windows.json', 'r', encoding='utf-8') as file:
    #     installs = json.load(file)

    # with open('all_cves_by_date.json', 'r', encoding='utf-8') as file:
    #     all_cves = json.load(file)
    with open('all_cves_by_date_normalized.json', 'r', encoding='utf-8') as file:
        all_cves = json.load(file)

    vulns = match_cves(installs, all_cves)
    #vulns = []

    fails = successes = 0
    found_installs = []
    for pkg in installs:
        if not pkg['cves']:
            fails += 1
        else:
            successes += 1
            found_installs.append(pkg)
    print(f"Number of successful matches in run: {successes}")
    print(f"Number of failed matches in run: {fails}")

    with open('results.json', 'w', encoding='utf-8') as file, open('results_abridged.json', 'w', encoding='utf-8') as file_abr, open('vulnerabilities.json', 'w', encoding='utf-8') as file_vulns:
        json.dump(installs, file, indent=2)
        json.dump(found_installs, file_abr, indent=2)
        json.dump(vulns, file_vulns, indent=2)

    print(f"Number of found IDs: {found_cve_ids}")

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")