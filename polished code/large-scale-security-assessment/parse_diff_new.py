import os
import json

# Initialize the result dictionary
results = {}

# Directory containing JSON files
directory = '.'  # Update this to your directory path

# Process each JSON file in the directory
for filename in os.listdir(directory):
    if filename.endswith('.json') and '2024' in filename:
        filepath = os.path.join(directory, filename)
        with open(filepath, 'r') as file:
            DIFF = json.load(file)

        protocol = filename.split('_')[0]  # Get the first part of the filename
        if protocol not in results and protocol != 'aggregated':
            results[protocol] = {
                "information_leakage": {
                    "2022": 0,
                    "2023": 0,
                    "2024": 0,
                    "not_vuln_2023": 0,
                    "not_vuln_2024": 0,
                    "offline_2023": 0,
                    "offline_2024": 0,
                    "new_vuln_2023": 0,
                    "new_vuln_2024": 0
                },
                "DoS": {
                    "2022": 0,
                    "2023": 0,
                    "2024": 0,
                    "not_vuln_2023": 0,
                    "not_vuln_2024": 0,
                    "offline_2023": 0,
                    "offline_2024": 0,
                    "new_vuln_2023": 0,
                    "new_vuln_2024": 0
                }
            }
            if protocol == 'xmpp':
                results[protocol]['weak_authentication'] = {
                    "2022": 0,
                    "2023": 0,
                    "2024": 0,
                    "not_vuln_2023": 0,
                    "not_vuln_2024": 0,
                    "offline_2023": 0,
                    "offline_2024": 0,
                    "new_vuln_2023": 0,
                    "new_vuln_2024": 0
                }
                del results[protocol]['DoS']

        for backend, values in DIFF.items():
            # Check for information leakage in 2022
            if 'vulnerability_classes' in values and 'information_leakage' in values['vulnerability_classes']:
                results[protocol]['information_leakage']["2022"] += 1

            if 'vulnerability_classes' in values and ('DoS' in values['vulnerability_classes'] or 'amplification_vulnerability' in values['vulnerability_classes']):
                results[protocol]['DoS']["2022"] += 1

            if 'vulnerability_classes' in values and 'weak_authentication' in values['vulnerability_classes']:
                results[protocol]['weak_authentication']["2022"] += 1

            if 'status_sep_2023' in values and values['status_sep_2023'] == "offline":
                if 'information_leakage' in values['vulnerability_classes']:
                    results[protocol]['information_leakage']['offline_2023'] += 1
                if 'DoS' in values['vulnerability_classes'] or 'amplification_vulnerability' in values['vulnerability_classes']:
                    results[protocol]['DoS']['offline_2023'] += 1
                if protocol == 'xmpp' and 'weak_authentication' in values['vulnerability_classes']:
                    results[protocol]['weak_authentication']['offline_2023'] += 1

            if 'update_sep_2023' in values:
                if values['update_sep_2023'] == {} and values['status_sep_2023'] == "online":
                    if 'information_leakage' in values['vulnerability_classes']:
                        results[protocol]['information_leakage']['not_vuln_2023'] += 1
                    if 'DoS' in values['vulnerability_classes'] or 'amplification_vulnerability' in values['vulnerability_classes']:
                        results[protocol]['DoS']['not_vuln_2023'] += 1
                    if protocol == 'xmpp' and 'weak_authentication' in values['vulnerability_classes']:
                        results[protocol]['weak_authentication']['not_vuln_2023'] += 1
                elif values['update_sep_2023'] != {} and values['status_sep_2023'] == "online":
                    update = values['update_sep_2023']
                    vulnerability_classes = values['vulnerability_classes']
                    if 'information_leakage' in vulnerability_classes and 'information_leakage' not in update:
                        results[protocol]['information_leakage']['not_vuln_2023'] += 1
                    if ('DoS' in vulnerability_classes or 'amplification_vulnerability' in vulnerability_classes) and ('DoS' not in update and 'amplification_vulnerability' not in update):
                        results[protocol]['DoS']['not_vuln_2023'] += 1
                    if protocol == 'xmpp' and 'weak_authentication' in vulnerability_classes and 'weak_authentication' not in update:
                        results[protocol]['weak_authentication']['not_vuln_2023'] += 1

                    if 'information_leakage' not in vulnerability_classes and 'information_leakage' in update:
                        results[protocol]['information_leakage']['new_vuln_2023'] += 1
                    if ('DoS' not in vulnerability_classes and 'amplification_vulnerability' not in vulnerability_classes) and ('DoS' in update or 'amplification_vulnerability' in update):
                        results[protocol]['DoS']['new_vuln_2023'] += 1
                    if protocol == 'xmpp' and 'weak_authentication' not in vulnerability_classes and 'weak_authentication' in update:
                        results[protocol]['weak_authentication']['new_vuln_2023'] += 1


                    if 'weak_authentication' in update and 'weak_authentication' in vulnerability_classes:
                        results[protocol]['weak_authentication']["2023"] += 1

            if 'status_jan2024' in values and values['status_jan2024'] == "offline":
                if 'information_leakage' in values['vulnerability_classes']:
                    results[protocol]['information_leakage']['offline_2024'] += 1
                if 'DoS' in values['vulnerability_classes'] or 'amplification_vulnerability' in values['vulnerability_classes']:
                    results[protocol]['DoS']['offline_2024'] += 1
                if protocol == 'xmpp' and 'weak_authentication' in values['vulnerability_classes']:
                    results[protocol]['weak_authentication']['offline_2024'] += 1

            if 'update_jan2024' in values:
                if values['update_jan2024'] == {}:
                    if 'information_leakage' in values['vulnerability_classes']:
                        results[protocol]['information_leakage']['not_vuln_2024'] += 1
                    if 'DoS' in values['vulnerability_classes'] or 'amplification_vulnerability' in values['vulnerability_classes']:
                        results[protocol]['DoS']['not_vuln_2024'] += 1
                    if protocol == 'xmpp' and 'weak_authentication' in values['vulnerability_classes']:
                        results[protocol]['weak_authentication']['not_vuln_2024'] += 1
                else:
                    update = values['update_jan2024']
                    vulnerability_classes = values['vulnerability_classes']
                    if 'information_leakage' in vulnerability_classes and 'information_leakage' not in update:
                        results[protocol]['information_leakage']['not_vuln_2024'] += 1
                    if ('DoS' in vulnerability_classes or 'amplification_vulnerability' in vulnerability_classes) and ('DoS' not in update and 'amplification_vulnerability' not in update):
                        results[protocol]['DoS']['not_vuln_2024'] += 1
                    if protocol == 'xmpp' and 'weak_authentication' in vulnerability_classes and 'weak_authentication' not in update:
                        results[protocol]['weak_authentication']['not_vuln_2024'] += 1

                    if 'information_leakage' not in vulnerability_classes and 'information_leakage' in update:
                        results[protocol]['information_leakage']['new_vuln_2024'] += 1
                    if ('DoS' not in vulnerability_classes and 'amplification_vulnerability' not in vulnerability_classes) and ('DoS' in update or 'amplification_vulnerability' in update):
                        results[protocol]['DoS']['new_vuln_2024'] += 1
                    if protocol == 'xmpp' and 'weak_authentication' not in vulnerability_classes and 'weak_authentication' in update:
                        results[protocol]['weak_authentication']['new_vuln_2024'] += 1

                    if 'weak_authentication' in update and 'weak_authentication' in vulnerability_classes:
                        results[protocol]['weak_authentication']["2024"] += 1
        if protocol != 'aggregated' and protocol != 'xmpp':
            results[protocol]['information_leakage']["2023"] = results[protocol]['information_leakage']['2022'] - results[protocol]['information_leakage']['not_vuln_2023'] - results[protocol]['information_leakage']['offline_2023']
            results[protocol]['DoS']["2023"] = results[protocol]['DoS']['2022'] - results[protocol]['DoS']['not_vuln_2023'] - results[protocol]['DoS']['offline_2023']
            results[protocol]['information_leakage']["2024"] = results[protocol]['information_leakage']['2022'] - results[protocol]['information_leakage']['not_vuln_2024'] - results[protocol]['information_leakage']['offline_2024']
            results[protocol]['DoS']["2024"] = results[protocol]['DoS']['2022'] - results[protocol]['DoS']['not_vuln_2024'] - results[protocol]['DoS']['offline_2024']


# Save the results to a new JSON file
with open('aggregated_results.json', 'w') as outfile:
    json.dump(results, outfile, indent=4)

print(json.dumps(results, indent=4))
