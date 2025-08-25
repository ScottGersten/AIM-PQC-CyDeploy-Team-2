import paramiko
import json
import time
from datetime import datetime
import re

found_cve_ids = 0           # Number of unqiue vulnerabilities found

# Common prefixes to extract for normalization logic
COMMON_PREFIXES = [
    'lib', 'python-', 'perl-', 'golang-', 'nodejs-', 
    'ms-', 'microsoft-', 'windows-', 'win-', 'vc-', 'vs-', 'vcredist-', 'dotnet-', 
    'adobe-', 'oracle-', 'java-', 'jdk-', 'jre-', 'openjdk-', 
    'msvc-', 'msxml-', 'msedge-', 'chromium-', 'chrome-', 'mozilla-', 'firefox-', 
    'sqlserver-', 'postgresql-', 'mysql-', 'mariadb-', 
    'vmware-', 'virtualbox-', 'cygwin-', 'mingw-'
]

# Get rid of common prefixes for better matching
def strip_prefix(name):
    for prefix in COMMON_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name

# Get rid of suffixes that will affect matching
def strip_trailing_version_suffix(name):
    return re.sub(r'\d+(off)?$', '', name)

# Fully normalize the string
def normalize_name(name):
    name = name.lower()
    name = name.replace('-', '')
    name = name.replace('_', '')
    name = strip_prefix(name)
    name = strip_trailing_version_suffix(name)
    return name

# Find vulnerable packages based on a matching name in a CVE description
def match_cves(installs, data):
    global found_cve_ids

    # Keys for CVEs that are no longer used
    INVALID_CVE = 'Rejected reason: DO NOT USE THIS CANDIDATE NUMBER.'
    INVALID_CVE_2 = 'rejected reason:'

    vulns = []
    seen_cves = set()

    for pkg in installs:
        name = pkg['name']
        norm_name = pkg['norm_name']
        first_year = pkg['first_year']
        last_year = pkg['last_year']
        # Set start year to 2025 if package has no date information
        if first_year is None:
            first_year = 2025
        
        # Only scan the necessary years
        for year in range(first_year, last_year + 1):
            year_str = str(year)
            if year_str not in data:
                continue
            # Parse out all the important data from the NVD JSON
            for item in data[year_str]:
                cve_id = item.get('id')
                description = item.get('description', '')
                raw = item.get('raw', {})
                impact = raw.get('impact', {})
                base_metric = impact.get('baseMetricV3', {})
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
                # Save CVE and CVSS data for CVEs that match a package
                if INVALID_CVE not in description and INVALID_CVE_2 not in description and name.lower() in description.lower():
                    cve_info = {
                                'id': cve_id, 
                                'desc': description, 
                                'attack_vector': attack_vector,
                                'attack_complexity': attack_complexity,
                                'privileges_required': privileges_required,
                                'user_interaction': user_interaction,
                                'scope': scope,
                                'confidentiality_impact': confidentiality_impact,
                                'integrity_impact': integrity_impact,
                                'availability_impact': availability_impact
                                }
                    pkg['cves'].append({'id': cve_id, 'desc': description})
                    if cve_id not in seen_cves:
                        vulns.append(cve_info)
                        seen_cves.add(cve_id)
                        found_cve_ids += 1
    
    return vulns


# Get the list of softwares from machine
def get_installs(ip, username='msfadmin', password='msfadmin', num_softwares = None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(ip, username=username, password=password)

    # Powershell command to get installed softwares list from the machine
    cmd = r'''powershell -Command "Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Json"'''

    stdin, stdout, stderr = ssh.exec_command(cmd)
    output = stdout.read().decode('utf-8')

    softwares = json.loads(output)

    software_count = 0
    packages = []
    for item in softwares:
        software_count += 1
        # Keep constraints for number of softwares
        if num_softwares is not None and software_count > num_softwares:
            break
        # Get the years and name and description information from each line
        name = item.get('DisplayName')
        version = item.get('DisplayVersion')
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
        software_count += 1
        if num_softwares is not None and software_count > num_softwares:
            break
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
    
    # with open(r'demo/software_lists/installed_windows_local_example.json', 'w', encoding='utf-8') as file:
    #     json.dump(packages, file, indent=2)
    with open(r'demo/software_lists/installed.json', 'w', encoding='utf-8') as file:
        json.dump(packages, file, indent=2)

    ssh.close()
    return packages

# Run the Windows-Local-Based scanner
def run_windows_local(connection, filename, num_softwares):
    start_time = time.time()

    # Check for software numbers constraint
    try:
        num_softwares = int(num_softwares)
    except Exception:
        num_softwares = None
    
    # Run the scanner using an SSH connection
    if connection == 'ssh':
        filename = 'demo/ssh_logins/' + filename
        with open(filename, 'r') as f:
            lines = f.read().splitlines()
            ip = lines[0]
            username = lines[1]
            password = lines[2]
        installs = get_installs(ip, username, password, num_softwares)

    # Run the scanner by reading from a file
    elif connection == 'file':
        filename = 'demo/software_lists/' + filename
        with open(filename, 'r', encoding='utf-8') as file:
            installs = json.load(file)
        if num_softwares is not None:
            installs = installs[0:num_softwares]

    else:
        installs = []

    with open(r'demo/data/all_cves_by_date_normalized.json', 'r', encoding='utf-8') as file:
        all_cves = json.load(file)

    vulns = match_cves(installs, all_cves)
    #vulns = []

    # Check and output number of vulnerable package
    fails = successes = 0
    found_installs = []
    for pkg in installs:
        if not pkg['cves']:
            fails += 1
        else:
            successes += 1
            found_installs.append(pkg)
    print(f"Number of vulnerable packages in run: {successes}")
    print(f"Number of safe packages in run: {fails}")

    # Write results dictionaries to files
    with open(r'demo/results/results.json', 'w', encoding='utf-8') as file, open(r'demo/results/results_abridged.json', 'w', encoding='utf-8') as file_abr, open(r'demo/results/vulnerabilities.json', 'w', encoding='utf-8') as file_vulns:
        json.dump(installs, file, indent=2)
        json.dump(found_installs, file_abr, indent=2)
        json.dump(vulns, file_vulns, indent=2)

    print(f"Number of found IDs: {found_cve_ids}")

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")