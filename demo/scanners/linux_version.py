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
        if first_year is None or last_year is None:
            continue
        
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
                if INVALID_CVE not in description and INVALID_CVE_2 not in description and norm_name in description:
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

def get_package_years(ssh, pkg):
    cmd = f"zgrep '^ --' /usr/share/doc/{pkg}/changelog.Debian.gz"
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        lines = stdout.read().decode().strip().splitlines()

        years = []
        for line in lines:
            date_match = re.search(r'\w{3}, \d{1,2} \w{3} \d{4}', line)
            if date_match:
                try:
                    date_obj = datetime.strptime(date_match.group(0), "%a, %d %b %Y")
                    years.append(date_obj.year)
                except ValueError:
                    continue

        if years:
            return years[-1], years[0]
        else:
            return None, None
    except Exception as e:
        return None, None

def get_installs(ip, username='msfadmin', password='msfadmin', num_softwares=None):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(ip, username=username, password=password)

    stdin, stdout, stderr = ssh.exec_command('dpkg -l')
    output = stdout.read().decode('utf-8')

    software_count = 0
    packages = []
    for line in output.splitlines():
        if line.startswith('ii'):
            software_count += 1
            if num_softwares is not None and software_count > num_softwares:
                break
            splits = line.split()
            first_year, last_year = get_package_years(ssh, splits[1])
            packages.append({
                'name': splits[1],
                'norm_name': normalize_name(splits[1]),
                'version': splits[2],
                'first_year': first_year,
                'last_year': last_year,
                'cves': []
            })

    # with open(r'demo/software_lists/installed_linux_example.json', 'w', encoding='utf-8') as file:
    #     json.dump(packages, file, indent=2)
    with open(r'demo/software_lists/installed.json', 'w', encoding='utf-8') as file:
        json.dump(packages, file, indent=2)

    ssh.close()
    return packages

def run_linux(connection, filename, num_softwares):
    start_time = time.time()

    try:
        num_softwares = int(num_softwares)
    except Exception:
        num_softwares = None

    if connection == 'ssh':
        filename = 'ssh_logins/' + filename
        with open(filename, 'r') as f:
            lines = f.read().splitlines()
            ip = lines[0]
            username = lines[1]
            password = lines[2]
            installs = get_installs(ip, username, password, num_softwares)

    elif connection == 'file':
        filename = 'software_lists/' + filename
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

    with open(r'demo/results/results.json', 'w', encoding='utf-8') as file, open(r'demo/results/results_abridged.json', 'w', encoding='utf-8') as file_abr, open(r'demo/results/vulnerabilities.json', 'w', encoding='utf-8') as file_vulns:
        json.dump(installs, file, indent=2)
        json.dump(found_installs, file_abr, indent=2)
        json.dump(vulns, file_vulns, indent=2)

    print(f"Number of found IDs: {found_cve_ids}")

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")
