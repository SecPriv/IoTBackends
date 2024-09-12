import json
from statistics import mean, stdev

coap_data = json.load(open('coap_total_2022.json', 'r'))

result = {}

versions = {}

ports = {}

vulnerabilities = {}

zyxel_AF = []
iotivity_AF = []

for endpoint, values in coap_data.items():

    if values != {}:

        if values['protocol'] != '':
            try:
                versions[values['protocol']] += 1
            except:
                versions[values['protocol']] = 1

        if len(values['vulnerabilities']) > 0:
            for vuln in values['vulnerabilities']:
                vuln_1 = vuln.split('\'')[0]
                try:
                    vulnerabilities[vuln_1] += 1
                except:
                    vulnerabilities[vuln_1] = 1

        if 'zyxel_AF' in values and float(values['zyxel_AF']) > 100:
            zyxel_AF.append(float(values['zyxel_AF']))   

        if 'iotivity_AF' in values and float(values['iotivity_AF']) > 100:
            iotivity_AF.append(float(values['iotivity_AF']))


result['versions'] = versions

result['zyxel_AF'] = {'max': max(zyxel_AF), 'mean': mean(zyxel_AF), 'stdev': stdev(zyxel_AF)}
result['iotivity_AF'] = {'max': max(iotivity_AF), 'mean': mean(iotivity_AF), 'stdev': stdev(iotivity_AF)}

# result['ports'] = ports

result['vulnerabilities'] = vulnerabilities

with open('summarized_results_2022.json', 'w') as output_file:
    json.dump(result, output_file)