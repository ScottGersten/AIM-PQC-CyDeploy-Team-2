import requests
import gzip
import json
import os
from datetime import datetime
import re

# Common prefixes to extract for normalization logic
COMMON_PREFIXES = [
    'lib', 'python-', 'perl-', 'golang-', 'nodejs-', 
    'ms-', 'microsoft-', 'windows-', 'win-', 'vc-', 'vs-', 'vcredist-', 'dotnet-', 
    'adobe-', 'oracle-', 'java-', 'jdk-', 'jre-', 'openjdk-', 
    'msvc-', 'msxml-', 'msedge-', 'chromium-', 'chrome-', 'mozilla-', 'firefox-', 
    'sqlserver-', 'postgresql-', 'mysql-', 'mariadb-', 
    'vmware-', 'virtualbox-', 'cygwin-', 'mingw-'
]

# Get rid of common prefixes for better matching
def strip_prefix(name):
    for prefix in COMMON_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name

# Get rid of suffixes that will affect matching
def strip_trailing_version_suffix(name):
    return re.sub(r'\d+(off)?$', '', name)

# Fully normalize the string (the descriptions in this case)
def normalize_name(name):
    name = name.lower()
    name = name.replace('-', '')
    name = name.replace('_', '')
    name = strip_prefix(name)
    name = strip_trailing_version_suffix(name)
    return name

START_YEAR = 2002                                       # First NVD year
END_YEAR = datetime.now().year                          # Last NVD year
BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/1.1'    # URL to access json.gz files

DATA_DIR = r'demo/data/nvd_feeds'                       # Path directory
os.makedirs(DATA_DIR, exist_ok=True)

# Download each of the NVD feeds from each year
def download_feed(year):
    url = f"{BASE_URL}/nvdcve-1.1-{year}.json.gz"
    local_path = os.path.join(DATA_DIR, f"nvdcve-1.1-{year}.json.gz")
    if not os.path.exists(local_path):
        print(f"Downloading {url}...")
        r = requests.get(url, stream=True)
        r.raise_for_status()
        with open(local_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    else:
        print(f"Feed for {year} already downloaded.")
    return local_path

# Parse each JSON file for the necessary information
def parse_feed(filepath):
    INVALID_CVE = 'Rejected reason: DO NOT USE THIS CANDIDATE NUMBER.'

    print(f"Parsing {filepath} ...")
    with gzip.open(filepath, 'rt', encoding='utf-8') as f:
        data = json.load(f)
    cve_items = data.get("CVE_Items", [])
    parsed_cves = []
    # Create dictionary with necessary information
    for item in cve_items:
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        description_data = item.get("cve", {}).get("description", {}).get("description_data", [])
        description = ""
        if description_data:
            description = description_data[0].get("value", "")
        parsed_cves.append({
            "id": cve_id,
            "description": normalize_name(description) if INVALID_CVE not in description else description,
            "raw": item
        })
    return parsed_cves

# Use the created dictionary to write all content to a single JSON file
def get_feeds():
    all_cves = {}
    for year in range(START_YEAR, END_YEAR + 1):
        path = download_feed(year)
        cves = parse_feed(path)
        all_cves[year] = cves

    print(f"Total CVEs parsed: {len(all_cves)}")
    
    with open(r"demo/data/all_cves_by_date_normalized.json", "w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2)
