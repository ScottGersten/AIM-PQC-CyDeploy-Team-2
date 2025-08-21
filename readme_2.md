# Vulnerability Scanner Using NVD Feeds and Quantum Computing Methods
This project demonstrates using information from the NVD Vulnerability feeds to detect potentially vulnerable packages on a Linux (Debian-based) or Windows machine and then determining the most prevalent vulnerabilities using quantum computing methods such as Quantum Annealing and Grover's Search.

## Project Overview
- Implements a script that parses all NVD feeds from 2002 to present and generates a combined JSON file with all necessary information about every vulnerability, using a method to normalize each CVE description for better matching.
- Implements three different scanner types that scan a machine for installed and running packages and runs it against the NVD information to see which of these packages are potentially vulnerable.
- Implements a QUBO matrix with a Quantum Annealer along with the weights from CVSS v3 to determine which of the potentially vulnerable packages are most imperative to address first.

## Project Structure and Logic

### Get NVD Feeds
- **Path:** `demo/data/get_nvd_feeds_norm.py`
- Makes a directory called `demo/data/nvd_feeds` which holds `nvdcve-1.1-200x.json.gz` files from 2002 to present.
- Creates a dictionary using every CVE from the NVD Feeds, normalizes the description for better matching, separates CVEs by their year, and writes it to `demo/data/all_cves_by_date_normalized.json`.

### Vulnerability Scanning
- **Path:** `demo/scanners/linux_version.py`, `demo/scanners/windows_local_version.py`, `demo/scanners/windows_vm_version.py`
- Gets a package list and creates a dictionary with entries for each package storing the package name, the normalized name, and the version.
- For the Linux-based scanner, accesses the Debian changelog and determines the first and last years each package was active. Adds this information to the dictionary.
- For the Windows-based scanners, sets the first year to the installation date (if the package has one, defaults to 2025 if not), and the last year to 2025.
- Creates the `demo/software_lists/installed.json` file with this dictionary.
- Searches through the dicionary of NVD information at only the years each package is active, for each package.
- Adds CVEs whos description has a match for a package's name to that package's information in the dictionary.
- Creates a set of potentially vulnerabilities that contains the CVE ID, description, and CVSS v3 information.
- Writes to `demo/results/results.json` with the full dictionary, to `demo/results/results_abridged.json` with only dictionary entries that have a potential vulnerability, and to `demo/results/vulnerabilities.json` with the set of potential vulnerability CVE IDs, descriptions, and the CVSS v3 information.

#### Linux (Debian) Based Scanner
- **Path:** `demo/scanners/linux_version.py`
- Gets a package list using a Debian command and creates a dictionary with entries for each package storing the package name, the normalized name, and the version.
- Uses another command to access the Debian changelog and determine the first and last years each package was active. Adds this information to the dictionary.
- Creates the `demo/software_lists/installed.json` file with this dictionary.
- Searches through the dicionary of NVD information at only the years each package is active, for each package.
- Adds CVEs whos description has a match for a package's name to that package's information in the dictionary.
- Writes to `demo/results/results.json` with the full dictionary, to `demo/results/results_abridged.json` with only dictionary entries that have a potential vulnerability, and to `demo/results/vulnerabilities.json` with a set of potential vulnerability CVE IDs and descriptions.
- Designed and tested using Metasploitable 2 Debian VM, uses Paramiko to connect to the machine.

#### Windows (Local and VM) Based Scanner
- **Path:** `demo/scanners/windows_local_version.py`, `demo/scanners/windows_vm_version.py`
- Gets a package list of installed softwares and currently running softwares using Powershell commands and creates a dictionary with entries for each package storing the package name, the normalized name, the version, and the installation date.
- Sets the first year to the installation date (if the package has one, defaults to 2025 if not), and the last year to 2025.
- Creates the `demo/software_lists/installed.json` file with this dictionary.
- Searches through the dicionary of NVD information at only the years each package is active, for each package.
- Adds CVEs whos description has a match for a package's name to that package's information in the dictionary.
- Writes to `demo/results/results.json` with the full dictionary, to `demo/results/results_abridged.json` with only dictionary entries that have a potential vulnerability, and to `demo/results/vulnerabilities.json` with a set of potential vulnerability CVE IDs and descriptions.
- Designed and tested on a local Windows 11 machine for the local version, uses Paramiko to connect to the machine.
- Designed and tested on Metasploitable 3 Windows 2008 VM for the VM version, uses WinRm to connect to the machine.

### Vulnerability Prioritization
- **Path:** `demo/qubo/cve_prioritization.py`
- Reads from `demo/results/vulnerabilities.json` to get a dictionary o



