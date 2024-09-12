	

import json

resources_coap = json.load(open('active_endpoints.json', 'r'))

active_resources = {}
unique_codes = {}

for e, r in resources_coap.items():
    for name, code in r.items():
        if code == "2_05":
            if name not in active_resources:
                active_resources[name] = 1
            else:
                active_resources[name] += 1
        if code not in unique_codes:
            unique_codes[code] = 1
        else:
            unique_codes[code] += 1

active_endpoints_ordered = dict(sorted(active_resources.items(), key=lambda item: item[1]))
print(unique_codes)
print(active_endpoints_ordered)