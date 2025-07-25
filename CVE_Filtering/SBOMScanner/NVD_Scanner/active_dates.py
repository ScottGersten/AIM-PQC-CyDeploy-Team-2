import paramiko
import re
from datetime import datetime
import time

def get_years_from_changelog(ssh, pkg):
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

# def get_first_year(ssh, pkg):
#     cmd = f"zgrep '^ --' /usr/share/doc/{pkg}/changelog.Debian.gz | tail -1"
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

# def get_last_year(ssh, pkg):
#     #cmd = f"zgrep -m 1 -E '^ --' /usr/share/doc/{pkg}/changelog.Debian.gz"
#     cmd = f"zgrep -E '^ --' /usr/share/doc/{pkg}/changelog.Debian.gz | head -1"
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
    
def get_years(ip, username='msfadmin', password='msfadmin'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)

    with open('installed.txt', 'r') as file:
        installs = file.read()

    first_years = {}
    last_years = {}
    count = 0
    for line in installs.splitlines():
        if line.startswith('ii'):
            # count += 1
            # if count > 100:
            #     break
            splits = line.split()
            pkg_name = splits[1]
            first_year, last_year = get_years_from_changelog(ssh, pkg_name)
            #first_year = get_first_year(ssh, pkg_name)
            if first_year:
                first_years[pkg_name] = first_year
            #last_year = get_last_year(ssh, pkg_name)
            if last_year:
                last_years[pkg_name] = last_year
    
    ssh.close()
    return first_years, last_years

def main():
    start_time = time.time()

    with open('ip.txt', 'r') as file:
        ip = file.read()
    
    release_years, end_years = get_years(ip)
    num_release = len(release_years)
    num_end = len(end_years)

    print(release_years)
    print(end_years)
    print(f"Release Years Found: {num_release}")
    print(f"End Years Found: {num_end}")

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")

if __name__ == '__main__':
    main()
                                   