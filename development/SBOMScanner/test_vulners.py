import requests
import json

def search_vulners(api_key, query='nginx 1.20.1'):
    url = 'https://vulners.com/api/v3/search/lucene/'
    headers = {'Content-Type': 'application/json'}
    payload = {
        'query': query,
        'apiKey': api_key
    }

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()

def search_vulners2(pkg, version, api_key):
    url = 'https://vulners.com/api/v3/burp/software/'
    params = {
        'software': pkg,
        'version': version,
        'apiKey': api_key
    }

    response = requests.get(url, params=params)
    response.raise_for_status()
    data = response.json()
    return data

def search_vulners3(api_key, query='nginx 1.20.1'):
    url = 'https://vulners.com/api/v3/search/lucene/'
    headers = {'Content-Type': 'application/json'}
    params = {
        'query': query,
        'apiKey': api_key
    }

    response = requests.get(url, params=params, headers=headers)
    response.raise_for_status()
    return response.json()

with open('vulners_api_key.txt', 'r') as file:
    api_key = file.read()

result = search_vulners(api_key, 'openssl 1.1.1k')
#result = search_vulners2('openssl', '1.1.1k', api_key)
#print(result)
with open('results.json', 'w', encoding='utf-8') as file:
    json.dump(result, file, indent=2)

# for doc in result.get('data', {}).get('search', []):
#     print(doc.get('id'), doc.get('title'))

cves = []
for item in result['data']['search']:
    source = item.get('_source', {})
    cve = source.get('cvelist', [])
    cves.extend(cve)
cves = sorted(list(set(cves)))
print(cves)