import paramiko
import re
from datetime import datetime
import time

def get_package_year(ssh, pkg):
    cmd = f"zgrep -m 1 -E '^ --' /usr/share/doc/{pkg}/changelog.Debian.gz"
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode().strip()
        if output:
            date_match = re.search(r'\w{3}, \d{1,2} \w{3} \d{4}', output)
            if date_match:
                date_str = date_match.group(0)
                date_obj = datetime.strptime(date_str, "%a, %d %b %Y")
                return date_obj.year
    except Exception as e:
        return None
    
def get_years(ip, username='msfadmin', password='msfadmin'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)

    with open('installed.txt', 'r') as file:
        installs = file.read()

    release_years = {}
    for line in installs.splitlines():
        if line.startswith('ii'):
            splits = line.split()
            pkg_name = splits[1]
            year = get_package_year(ssh, pkg_name)
            if year:
                release_years[pkg_name] = year
    
    ssh.close()
    return release_years

def main():
    start_time = time.time()

    with open('ip.txt', 'r') as file:
        ip = file.read()
    
    #release_years = len(get_years(ip))
    release_years = get_years(ip)
    
    print(release_years)

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")

if __name__ == '__main__':
    main()
                                   