import requests
import gzip
import json
import os
from datetime import datetime

START_YEAR = 2002
END_YEAR = datetime.now().year
BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/1.1'

DATA_DIR = 'nvd_feeds'
os.makedirs(DATA_DIR, exist_ok=True)

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

def parse_feed(filepath):
    print(f"Parsing {filepath} ...")
    with gzip.open(filepath, 'rt', encoding='utf-8') as f:
        data = json.load(f)
    cve_items = data.get("CVE_Items", [])
    parsed_cves = []
    for item in cve_items:
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        description_data = item.get("cve", {}).get("description", {}).get("description_data", [])
        description = ""
        if description_data:
            description = description_data[0].get("value", "")
        parsed_cves.append({
            "id": cve_id,
            "description": description,
            "raw": item
        })
    return parsed_cves

def main():
    all_cves = {}
    for year in range(START_YEAR, END_YEAR + 1):
        path = download_feed(year)
        cves = parse_feed(path)
        all_cves[year] = cves

    print(f"Total CVEs parsed: {len(all_cves)}")
    
    with open("all_cves_by_date.json", "w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2)

if __name__ == "__main__":
    main()
