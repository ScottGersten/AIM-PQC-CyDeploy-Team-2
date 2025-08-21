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

### Vulnerability Prioritization
- **Path:** `demo/qubo/cve_prioritization.py`
- Reads from `demo/results/vulnerabilities.json` to get a dictionary of CVE IDs, descriptions, and CVSS v3 information.
- Creates maps of the CVSS v3 string metric to a numerical weight given by CVSS v3.
- Goes through the set of vulnerabilities and creates a new dictionary that replaces each string metric with its numerical weight.
- Creates a list of the weight of each vulnerability using each of the CVSS v3 metrics.
- Creates a QUBO matrix where each diagonal is the negative weight of a vulnerability offset with the penalty to encourage vulnerabilities with high weights.
- Sets the off diagonals to double the penalty to discourage picking multiple items.
- Modifies the diagonal to limit the number of vulnerabilites that are selected.
- Uses D-WAVE's Simulated Annealing Sampler to mimic running the QUBO through a Quantum Annealer.
- Based on the binary results, determines which vulnerabilities are the most important and writes them to `demo/results/cves_to_prioritize.json`.

## How to Run
Be in the root directory

### Prerequisites
```bash
git clone https://github.com/ScottGersten/AIM-PQC-CyDeploy-Team-2.git
```
```bash
pip install requests dwave-ocean-sdk paramiko pywinrm
```

### Creating the NVD Feeds and JSON
```bash
python -m demo.main --version get_data --connection get_data --filename none
```

### Running the Scanners
Use the --num_softwares flag to specify an integer if you wish to limit the amount of softwares that will be scanned. The default is to scan all softwares found on a machine.

#### Running from SSH

##### Linux
- Create `demo/ssh_logins/linux.txt` with SSH information.
- Ensure Debian-based machine can be logged into (modeled with Metasploitable 2 VM).
```bash
python -m demo.main --version linux --connection ssh --filename linux.txt --num_softwares all
```

##### Windows Local
- Create `demo/ssh_logins/windows_local.txt` with SSH information.
- Ensure OpenSSH.Server is installed and running on your Windows machine.
```bash
python -m demo.main --version windows_local --connection ssh --filename windows_local.txt --num_softwares all
```

##### Windows VM
- Create `demo/ssh_logins/windows_vm.txt` with SSH information.
- Ensure Windows-based machine can be logged into (modeled with Metasploitable 3).
```bash
python -m demo.main --version windows_vm --connection ssh --filename windows_vm.txt --num_softwares all
```

#### Running from File

##### Linux
```bash
python -m demo.main --version linux --connection file --filename installed_linux_example.json --num_softwares all
```

##### Windows Local
```bash
python -m demo.main --version windows_local --connection file --filename installed_windows_local_example.json --num_softwares all
```

##### Windows VM
```bash
python -m demo.main --version windows_vm --connection file --filename installed_windows_vm_example.json --num_softwares all
```

### Running the Prioritization
```bash
python -m demo.main --version qubo --connection qubo --filename none
```

## Future Work
- The QUBO can be made more sophisticated by adding weights to each variable when finding the total weight of each vulnerability. Currently, all variables from CVSS v3 equally make up the total weight score. This can be adjusted by weighting each variable in the summation in terms of it should matter more or less to the vulnerability's overall prevalence.
- The Windows Local and Windows VM method do not have the sophisticated date ranges that the Debian method does. There are no changelogs available through Powershell in the same way there is for Debian. These changelogs based on the first and most recent updates to a package gave a good estimate to the active dates of the package. Without the ability to do this on Windows, we were left defaulting to either the package's installation date on the computer (which is not accurate to its beginning date) or 2025 to safeguard the scanner from scanning every single NVD feed. Finding a way to establish a date range for the Windows versions would make the scanner more practical.