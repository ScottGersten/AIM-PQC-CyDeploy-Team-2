# AIM-PQC-CyDeploy-Team-2

## Quantum Theory:

## Running by-date method:

- Navigate to `CVE_Filtering/SBOMScanner/NVD_Scanner`
- Run `get_nvd_feeds_by_date.py` to create the `nvd_feeds` directory with all NVD feed JSONs. This will also create `all_cves_by_date.json`, which is the file the by-date method will use.
- Then run `nvd_method_by_date.py`, which is the main logic. Currently, this file works for a Debian Linux VM with the SSH login of `msfadmin` for both the username and password. The IP address of the VM is read from the `ip.txt` file. Running this on the VM will create an `installed.json` file. Once this file is created, the main method can be edited to not use the `get_installs()` function and instead read from the `installed.json` file. The run will create the `results.json` and `results_abridged.json` files:
  - `results.json` contains every package from `installed.json`, each with an added `CVEs` field listing the matching CVE IDs.
  - `results_abridged.json` is a shortened version that only includes packages with matching CVE IDs.

- Currently in-progress:
  - Adding another field to the results dictionary that holds the vulnerability description for each CVE that is found. A `vulnerabilities.json` file may also be created to display just the vulnerabilities—this will serve as the primary user-facing output.
  - Using the CPEs method to reduce the list of found CVEs and improve accuracy.
  - Creating a Windows-compatible version of the logic to scan Windows machines. The system will then detect the OS and run the appropriate logic. Even if this is not automated, both versions will be available, and the user can choose which to run based on the system type.
