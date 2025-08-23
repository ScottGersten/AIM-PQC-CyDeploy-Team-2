# Quanutm-Inspired Hybrid Vulnerability Scanner
This scanner utilizes information from Ubuntu, NVD, and Debain databases to identify vulnerable packages on a Linux machine. Then it orders all the detected vulnerable pacakges in a list using Grover's Search. At the top of the list is the package with the most CVE matches and then it goes down the list while displaying the amount of CVE matches for each vulnerable package.

## Project Overview
- Parses a list of software packages in the `dpkg -l` format from the installed.txt file.
- Scans installed.txt and conducts package versions detection and keyword search.
- Cross-refrences installed.txt against the Ubuntu, Debain, and NVD databases 
- Identifies which packages are potentially vulnerable and matches them with the relevant CVEs
- Retrieves detailed CVE information. 
- Constructs a Grover oracle to mark the vulnerable software packages.
- Applies Gorver's Search (Qiskit Simulation) to priortize which ones should be addressed first.

## Project Structure and Logic

### Ubuntu, NVD, and Debain Databases
- **Path:** `combined_demo\ubuntu.json`, `combined_demo\all_cves.json`
- The first one is the JSON file for the Ubuntu CVE database.
- The second path is the JSON file for the NVD CVE database
- The Debian database uses a URL which is already integrated in the scanner.

### Grover Integrated Vulnerability Scanning
- **Path:** `combined_demo\grover_vuln_scan.py`
- Constructs a Grover oracle to mark the high-priority vulnerable software packages based on the amount of CVE matches.
- Applies Grover's Search to amplify th
- Outputs a list of all the marked packages in order with the package with the most CVEs at the top of the list.
- The CVE matching results are written to `combined_demo/grover_combined_results.json`. 

## How to Run
Be in the `combined_demo` directory

### Prerequisites
```bash
git clone https://github.com/ScottGersten/AIM-PQC-CyDeploy-Team-2.git
```

**Qiskit Virtual Environment:**
```bash
python -m venv qiskit-env - Creates a Qiskit Virtual Environment.
```
```bash
powershell -ExecutionPolicy Bypass -NoProfile - Only run this command if the command below is being blocked by Powershell's default security settings.
```
```bash
.\qiskit-env\Scripts\Activate - Activates the Qiskit Virtual Environment.
```
```bash
pip install qiskit 
```
```bash
pip install qiskit_aer
```

### Running the Scanner
- Create `combined_demo/installed.txt`
- Add all the packages discovered on the environment to the installed.txt file in `dpkg -l` format. 
- Run scanner to analyze the software packages and priortize results.

## Future Work
- Implement real quantum hardware to test Grover's Search on actual quantum devices. We can also examine the quantum advantages like quadratic speed-up
- Enhance prioritization results by integrating CVSS scores for all the flagged packages.
