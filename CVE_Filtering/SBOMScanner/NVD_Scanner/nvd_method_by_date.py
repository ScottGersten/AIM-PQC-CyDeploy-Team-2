import paramiko
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime
import re
import threading

found_cve_ids = 0

COMMON_PREFIXES = ['lib', 'python-', 'perl-', 'golang-', 'nodejs-']

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

    for pkg in installs:
        name = pkg['name']
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
                #if name.lower() in description.lower():
                if normalize_name(name) in normalize_name(description):
                    pkg['cves'].append(cve_id)
                    found_cve_ids += 1

# def match_cves(installs, data, present_year=2025):
#     global found_cve_ids

#     for pkg in installs:
#         name = pkg['name']
#         release_year = pkg['release_year']
#         if release_year is None:
#             continue
        
#         for year in range(release_year, present_year + 1):
#             year_str = str(year)
#             if year_str not in data:
#                 continue
#             for item in data[year_str]:
#                 cve_id = item.get('id')
#                 description = item.get('description', '')
#                 if name.lower() in description.lower():
#                     pkg['cves'].append(cve_id)
#                     found_cve_ids += 1

# def match_cves(installs, data, year_offset=5):
#     global found_cve_ids

#     for pkg in installs:
#         name = pkg['name']
#         release_year = pkg['release_year']
#         if release_year is None:
#             continue
        
#         for year in range(release_year, release_year + year_offset + 1):
#             year_str = str(year)
#             if year_str not in data:
#                 continue
#             for item in data[year_str]:
#                 cve_id = item.get('id')
#                 description = item.get('description', '')
#                 if name.lower() in description.lower():
#                     pkg['cves'].append(cve_id)
#                     found_cve_ids += 1

# def get_package_year(ssh, pkg):
#     cmd = f"zgrep -m 1 -E '^ --' /usr/share/doc/{pkg}/changelog.Debian.gz"
#     try:
#         stdin, stdout, stderr = ssh.exec_command(cmd)
#         output = stdout.read().decode().strip()
#         if output:
#             date_match = re.search(r'\w{3}, \d{1,2} \w{3} \d{4}', output)
#             if date_match:
#                 date_str = date_match.group(0)
#                 date_obj = datetime.strptime(date_str, "%a, %d %b %Y")
#                 return date_obj.year
#     except Exception as e:
#         return None

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

def get_installs(ip, username='msfadmin', password='msfadmin'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(ip, username=username, password=password)

    stdin, stdout, stderr = ssh.exec_command('dpkg -l')
    output = stdout.read().decode('utf-8')

    # with open('installed.txt', 'w', encoding='utf-8') as file:
    #     file.write(output)

    packages = []
    for line in output.splitlines():
        if line.startswith('ii'):
            splits = line.split()
            first_year, last_year = get_package_years(ssh, splits[1])
            packages.append({
                'name': splits[1],
                'version': splits[2],
                #'description': ''.join(splits[3:]),
                #'release_year': get_package_year(ssh, splits[1]),
                'first_year': first_year,
                'last_year': last_year,
                'cves': []
            })

    with open('installed.json', 'w', encoding='utf-8') as file:
        json.dump(packages, file, indent=2)

    ssh.close()
    return packages

def main():
    start_time = time.time()

    with open('ip.txt', 'r') as f:
        ip = f.read()
    #installs = get_installs(ip)
    with open('installed.json', 'r', encoding='utf-8') as file:
        installs = json.load(file)

    with open('all_cves_by_date.json', 'r', encoding='utf-8') as file:
        all_cves = json.load(file)

    match_cves(installs, all_cves)

    # matched_cves = match_cves(installs, all_cves)
    # with open('matched.json', 'w', encoding='utf-8') as file:
    #     json.dump(matched_cves, file, indent=2)

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

    with open('results.json', 'w', encoding='utf-8') as file, open('results_abridged.json', 'w', encoding='utf-8') as file_abr:
        json.dump(installs, file, indent=2)
        json.dump(found_installs, file_abr, indent=2)

    print(f"Number of found IDs: {found_cve_ids}")

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")

if __name__ == '__main__':
    main()