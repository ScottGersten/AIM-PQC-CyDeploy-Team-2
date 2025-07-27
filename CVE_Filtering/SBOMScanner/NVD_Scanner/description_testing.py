import json

def main():
    with open('all_cves.json', 'r', encoding='utf-8') as f1:
        data = json.load(f1)

    descriptions = {}

    for item in data:
        cve_id = item.get('id')
        desc = item.get('description', '')

        name = 'postgresql'
        if name.lower() in desc.lower():
            #print(f"\n{desc}\n")
            descriptions[cve_id] = desc
    
    with open('description_testing.json', 'w', encoding='utf-8') as f1:
        json.dump(descriptions, f1, indent=2)

if __name__ == '__main__':
    main()