import json

FILE_2024 = json.load(open('coap_diff_2024.json'))
VULNERABLE_2022 = json.load(open('coap/vulnerable_2022.json', 'r'))

backends_vulnerable_2022 = set()
countries_2022 = {}
providers_2022 = {}

backends_vulnerable_2023 = set()
countries_2023 = {}
providers_2023 = {}
offline_2023 = set()

europe_codes = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 
    'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE']

def add_element_to_map(field, map):
    if field:
        if field not in map:
            map[field] = 1
        else:
            map[field] += 1

def country_categorization(e):
    if e in europe_codes:
        return 'EU'
    elif e == 'CN':
        return 'CN'
    elif e == 'US':
        return 'US'
    elif e == 'RU':
        return 'RU'
    else:
        return 'Other'

def check_if_resources_present(json_obj):
    if 'information_leakage' in json_obj:
        for vuln in json_obj['information_leakage']:
            if vuln['scanning_technique'] == 'resource_enumeration_via_HEAD':
                return True
    return False


for backend, v in FILE_2024.items():
    try:
        country = country_categorization(VULNERABLE_2022[backend]['country'])
    except:
        country = None
    if 'vulnerability_classes' in v and 'information_leakage' in v['vulnerability_classes']:
        for vuln in v['vulnerability_classes']['information_leakage']:
            if vuln['scanning_technique'] == 'resource_enumeration_via_HEAD':
                backends_vulnerable_2022.add(backend)
                add_element_to_map(v['provider'], providers_2022)
                add_element_to_map(country, countries_2022)

    #     if v['status_sep_2023'] == 'offline':
    #         offline_2023.add(backend)

    if 'update_sep_2023' in v and check_if_resources_present(v['update_sep_2023']) or (('vulnerability_classes' in v and check_if_resources_present(v['vulnerability_classes'])) and v['status_sep_2023'] == 'online' and 'update_sep_2023' not in v):

        backends_vulnerable_2023.add(backend)
        add_element_to_map(country ,countries_2023)
        add_element_to_map(v['provider'], providers_2023)

    
print(len(backends_vulnerable_2022))
print(countries_2022)
print(providers_2022)

print(countries_2023)