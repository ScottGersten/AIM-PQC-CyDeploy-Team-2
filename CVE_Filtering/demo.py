import requests

def get_redhat_cves_by_package(package_name):
    url = "https://access.redhat.com/hydra/rest/securitydata/cve.json?after=2024-07-05&before=2024-07-06"
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; CVE-Scanner/1.0)"
    }
    params = {
        "package": package_name
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVEs for {package_name}: {e}")
        return []

# Example usage
results = get_redhat_cves_by_package("openssl")
for cve in results[:5]:
    print(cve["CVE"], "-", cve.get("severity", "N/A"))
