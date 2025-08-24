# Quantum-Inspired Hybrid Vulnerability Scanner
This scanner utilizes information from Ubuntu, NVD, and Debian databases to identify vulnerable packages on a Linux machine. Then it orders all the detected vulnerable packages in a list using Grover's Search. At the top of the list is the package with the most CVE matches, followed by others in descending order of severity. The number of CVE matches for each vulnerable package is displayed.

## Project Overview
- Parses a list of software packages in the `dpkg -l` format from the installed.txt file.
- Scans installed.txt and conducts package versions detection and keyword search.
-  Cross-references installed.txt against the Ubuntu, Debian, and NVD databases 
- Identifies which packages are potentially vulnerable and matches them with the relevant CVEs
- Retrieves detailed CVE information. 
- Applies Gorver's Search using Qiskit's AER Simulator to prioritize which packages should be addressed first.

## Project Structure and Logic

### Ubuntu, NVD, and Debian Databases
- **Path:** `combined_demo\ubuntu.json`, `combined_demo\all_cves.json`
- The first one is the JSON file for the Ubuntu CVE database.
- The second path is the JSON file for the NVD CVE database
- The Debian database uses a URL, which is already integrated in the scanner.

### Grover Integrated Vulnerability Scanning
- **Path:** `combined_demo\grover_vuln_scan.py`
- The quantum circuit is executed on Qiskit's AER simulator 1024 times. 
- Constructs a Grover oracle to mark the high-priority vulnerable software packages based on the number of CVE matches. This tells the scanner which software packages to focus on.
- Applies the diffusion operator to amplify the flagged packages, making them more likely to appear at the top in the final output. This increases the probability that the most significant issues are discovered first.
- The vulnerable package that appears the most often as the top vulnerable package after each run is considered the highest-priority vulnerable package.
- Grover's Search is applied to reorder all the marked packages with the most critical ones at the top of the list.
- The CVE matching results are displayed in the order of the Grover prioritized list, which is written to `combined_demo/grover_combined_results.json`. 

## How to Run
Be in the `combined_demo` directory

### Prerequisites
```bash
git clone https://github.com/ScottGersten/AIM-PQC-CyDeploy-Team-2.git
```

**Qiskit Virtual Environment:**
```bash
python -m venv qiskit-env 
```
- Creates a Qiskit Virtual Environment.

```bash
powershell -ExecutionPolicy Bypass -NoProfile 
```
- Only run this command if the command below is being blocked by PowerShell's default security settings.

```bash
.\qiskit-env\Scripts\Activate 
```
- Activates the Qiskit Virtual Environment.

```bash
pip install qiskit 
```
```bash
pip install qiskit_aer
```

### Running the Scanner
- Create `combined_demo/installed.txt`
- Add all the packages discovered in the environment to the installed.txt file in `dpkg -l` format. 
- Run scanner to analyze the software packages and prioritize results.
```bash
python grover_vuln_scan.py 
```

## Future Work
- Implement real quantum hardware to test Grover's Search on actual quantum devices. We can also examine the quantum advantages, like quadratic speed-up
- Enhance prioritization results by integrating CVSS scores for all the flagged packages.
