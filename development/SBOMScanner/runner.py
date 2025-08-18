import subprocess
import os
import sys

directory = os.path.dirname(os.path.abspath(__file__))
#print(directory)

files = [
    'demo.py',
    'get_vulns.py'
]

for file in files:
    path = os.path.join(directory, file)
    print(f"\nRunning {file}:\n{'=' * 40}")
    subprocess.run([sys.executable, path])