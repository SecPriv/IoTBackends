import json
from statistics import mean, stdev

mqtt_data = json.load(open('mqtt_parsed_2022.json', 'r'))

result = {}

connection_success = 0
connection_fail = 0

versions = {}

connected_hosts = []

number_unique_topics = []

ports = {}

vulnerabilities = {}

for host, element in mqtt_data.items():

    if element != {}:

        if 'connection' in element:
            if element['connection'] == 'failed' or element['connection'] == 'error':
                connection_fail += 1
            elif element['connection'] == 'success':
                connection_success += 1

            if element['version'] != '':
                try:
                    versions[element['version']] += 1
                except:
                    versions[element['version']] = 1

            if element['connected_hosts'] != '':
                try:
                    number = int(element['connected_hosts'])
                    connected_hosts.append(number)
                except:
                    pass

            number_unique_topics.append(element['number_unique_topics'])

            try:
                try:
                    ports[element['port']] += 1
                except:
                    ports[element['port']] = 1
            except:
                pass

            try:
                if len(element['vulnerabilities']) > 0:
                    for vuln in element['vulnerabilities']:
                        vuln_1 = vuln.split('\'')[0]
                        try:
                            vulnerabilities[vuln_1] += 1
                        except:
                            vulnerabilities[vuln_1] = 1
            except:
                pass

result['connection'] = {}
result['connection']['success'] = connection_success
result['connection']['fail'] = connection_fail

result['versions'] = versions

if len(connected_hosts) > 0:
    result['connected_hosts'] = {}
    result['connected_hosts']['average'] = mean(connected_hosts)
    if len(connected_hosts) > 1:
        result['connected_hosts']['stdev'] = stdev(connected_hosts)
    result['connected_hosts']['min'] = min(connected_hosts)
    result['connected_hosts']['max'] = max(connected_hosts)

if len(number_unique_topics) > 0:
    result['number_unique_topics'] = {}
    result['number_unique_topics']['average'] = mean(number_unique_topics)
    if len(number_unique_topics) > 1:
        result['number_unique_topics']['stdev'] = stdev(number_unique_topics)
    result['number_unique_topics']['min'] = min(number_unique_topics)
    result['number_unique_topics']['max'] = max(number_unique_topics)

result['ports'] = ports

result['vulnerabilities'] = vulnerabilities

with open('summarized_results_2022.json', 'w') as output_file:
    json.dump(result, output_file)