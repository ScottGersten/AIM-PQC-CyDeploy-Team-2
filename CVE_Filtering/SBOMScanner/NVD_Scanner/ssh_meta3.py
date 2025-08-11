import winrm
import time
import json
import paramiko

def winrm_test():
    start_time = time.time()

    session = winrm.Session(
        '192.168.56.102',
        auth=('vagrant', 'vagrant')
    )

    cmd = r'''powershell -Command "Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Json"'''
    #esult = session.run_cmd(cmd)
    #print(json.loads(result.std_out.decode('cp1252').strip()))
    result = session.run_ps('ls')
    print(result.std_out.decode())

    end_time = time.time() - start_time
    print(f"Execution Time: {end_time:.4f}")

def paramiko_test():
    ip = "192.168.56.102"
    username = "vagrant"
    password = "vagrant"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password, allow_agent=False, look_for_keys=False)

    stdin, stdout, stderr = ssh.exec_command("hostname")
    print(stdout.read().decode())

    ssh.close()

winrm_test()
#paramiko_test()
