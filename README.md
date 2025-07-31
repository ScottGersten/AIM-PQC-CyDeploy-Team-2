# AIM-PQC-CyDeploy-Team-2

## Quantum Theory:

- Can use a QUBO problem to figure out which CVEs are of highest priority to address. In a list of potentially hundreds of CVEs, this will give more direction to the user. Can use D-WAVE's Quantum Annealer to create this QUBO problem.
  - The goal is to create a subset of CVE IDs and descriptions that are of highest priority to be addressed first.
  - Variables (for `N` CVEs):
    - Let `x_i = 1` if `CVE_i` should be treated with higher priority
    - Let `x_i = 0` if `CVE_i` should NOT be treated with higher priority
    - Let `s_i` be the CVSS severity score of the vulnerability (scale from 1-10)
    - Let `t_i` be the estimated time for a patch or fix to the vulnerability (real number as hours)
    - Let `p_i` be the importance of the package to the system as a whole (scale from 1-5)
  - Define a benefit as `b_i = alpha * s_i + beta * p_i`, where `alpha` and `beta` are weights.
  - The maximum benefit is a minimization of cost so `max_benefit = - (summation, i = 1, N) of b_i * x_i`.
  - There is a penalty based on the time it will take to patch.
    - `total_time = (summation, i = 1, N) of t_i * x_i`
    - Want the `total_time <= T_max` which is a maximum time limit we will set
    - So `penalty = P * (total_time - T_max) ^ 2`
  - Final QUBO equation is `Q(x) = max_benefit + penalty`
  - Can build in code using D_WAVE's Quantum Annealer or pyqubo module.

## Running by-date method:

- Navigate to `CVE_Filtering/SBOMScanner/NVD_Scanner`
- Run `get_nvd_feeds_by_date.py` to create the `nvd_feeds` directory with all NVD feed JSONs. This will also create `all_cves_by_date.json`, which is the file the by-date method will use.
- Then run `nvd_method_by_date.py`, which is the main logic. Currently, this file works for a Debian Linux VM with the SSH login of `msfadmin` for both the username and password. The IP address of the VM is read from the `ip.txt` file. Running this on the VM will create an `installed.json` file. Once this file is created, the main method can be edited to not use the `get_installs()` function and instead read from the `installed.json` file. The run will create the `results.json`, `results_abridged.json`, and `vulnerabilities.json` files:
  - `results.json` contains every package from `installed.json`, each with an added `CVEs` field listing the matching CVE IDs and the description that goes along with the ID.
  - `results_abridged.json` is a shortened version that only includes packages with matching CVE IDs and their descriptions.
  - `vulnerabilities.json` is a list of CVE IDs and their matching descriptions, excluding repeated IDs and descriptions. This should be the main output the user will care about.

- Currently in-progress:
  - Using the CPEs method to reduce the list of found CVEs and improve accuracy.
  - Creating a Windows-compatible version of the logic to scan Windows machines. The system will then detect the OS and run the appropriate logic. Even if this is not automated, both versions will be available, and the user can choose which to run based on the system type.
  - Researching ways that quantum computing can be used within this algorithm.
