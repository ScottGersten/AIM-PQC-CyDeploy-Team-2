import subprocess
import time
import json
import platform
import threading
import time

target_host = ["192.168.1.0"]


def target_info():
    info = platform.platform()
    
    with open ("scan_results.json", 'w') as results:
        json.dump(info, results, indent=2)
    
    return info

def thread():



def agent_scanner():
    info = target_info()




