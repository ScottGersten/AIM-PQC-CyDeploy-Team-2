import argparse
from demo.data.get_nvd_feeds_norm import get_feeds
from demo.scanners.linux_version import run_linux
from demo.scanners.windows_local_version import run_windows_local
from demo.scanners.windows_vm_version import run_windows_vm
from demo.qubo.cve_prioritization import run_prioritization

def main():
    # Create command-line arguments for running
    parser = argparse.ArgumentParser(description='QUBO vulnerability detection demo')
    parser.add_argument('--version', choices=['linux', 'windows_local', 'windows_vm', 'get_data', 'qubo'], required=True, help='Choose version')
    parser.add_argument('--connection', choices=['ssh', 'file', 'get_data', 'qubo'], required=True, help='Either SSH to find softwares or use file with softwares')
    parser.add_argument('--filename', required=True, help='Enter filename that contains either SSH credentials or list of softwares')
    parser.add_argument('--num_softwares', default=None, help='Enter number of softwares to scan through, defaults to all')
    args = parser.parse_args()
    print(f"{args.version} {args.connection} {args.filename} {args.num_softwares}")

    # Call each file based on the version to be run

    if args.version == 'get_data':
        get_feeds()
    
    elif args.version == 'linux':
        run_linux(args.connection, args.filename, args.num_softwares)

    elif args.version == 'windows_local':
        run_windows_local(args.connection, args.filename, args.num_softwares)
    
    elif args.version == 'windows_vm':
        run_windows_vm(args.connection, args.filename, args.num_softwares)

    elif args.version == 'qubo':
        run_prioritization()


if __name__ == '__main__':
    main()