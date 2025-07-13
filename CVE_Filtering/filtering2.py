import paramiko

def get_installs(ip, username='msfadmin', password='msfadmin'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(ip, username=username, password=password)

    stdin, stdout, stderr = ssh.exec_command('dpkg -l')
    output = stdout.read().decode('utf-8')

    ssh.close()

    with open('installed.txt', 'w', encoding='utf-8') as file:
        file.write(output)

    return output

def parse_installs(installs):
    packages = []
    for line in installs.splitlines():
        if line.startswith('ii'):
            splits = line.split()
            packages.append({
                'name': splits[1],
                'version': splits[2],
                'description': ''.join(splits[3:])
            })
    return packages
    
output = get_installs('192.168.56.101')
installs = parse_installs(output)

print(installs)