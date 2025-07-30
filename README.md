# AIM-PQC-CyDeploy-Team-2

## Quantum Theory:


## Running by-date method:
    - **1** - Navigate to CVE_Filtering/SBOMScanner/NVD_Scanner
    - **2** - Run 'get_nvd_feeds_by_date.py' to create the nvd_feeds directory with all NVD feed jsons. Will also create all_cves_by_date.json which is the file the by-date method will use.
    - **3** - Then run 'nvd_method_by_date.py' which is the main logic. Right now this file works for a Debian Linux VM with the ssh login of 'msfadmin' for the username and password and the ip address of the VM within the 'ip.txt' file. Running on the VM will create an 'installed.json' file. Once this file is created the main method can be edited to not use the get_installs() function and just read from the 'installed.json' file. The run will create the 'results.json' and 'results_abridged.json' files. 'results.json' holds every package appearing in the 'installed.json' file with the added CVEs field to the dictionary which holds the matching CVE IDs. 'results_abridged.json' is a shortened version of 'results.json' holding only the packages that had matching CVE IDs. 
    - **Currently in-progress**:
        - **1** - Adding in another field to the results dictionary that holds the vulnerability description for each CVE that is found. Will likely also create a vulnerabilities file that will show just the vulnerabilities present as this is the output the user will see.
        - **2** - Using the CPEs method to reduce the list of found CVEs to be more accurate.
        - **3** - Creating another windows version of the logic that will work for Windows machines instead of a Linux machine. Then putting the two versions together and determining the OS of the system first, then choosing which version to use. Even if our logic does not implicitly choose, will have the two version that can be chosen between by the person running the code based on which system they want to scan.

