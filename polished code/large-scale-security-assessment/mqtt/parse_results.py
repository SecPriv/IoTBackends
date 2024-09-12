import os, json

directory = './security-results/'

mqtt_results = {}

#iterate over all the subfolders
for filename in os.listdir(directory):

    #iterate over sub-subfolders
    for files in os.listdir(os.path.join(directory, filename)):

        f = os.path.join(directory, filename, files)

        try:
            mqtt_results[filename]
        except:
            mqtt_results[filename] = {}

        if os.path.isfile(f) and 'mqtt.json' in files:
            result = json.load(open(f, 'r'))

            try:
                mqtt_results[filename]['connection'] = result['connection']
            except:
                mqtt_results[filename]['connection'] = 'failed'

            try:
                mqtt_results[filename]['version'] = result['system_info']['version']
            except:
                mqtt_results[filename]['version'] = ''

            try:
                mqtt_results[filename]['connected_hosts'] = result['system_info']['connected']
            except:
                mqtt_results[filename]['connected_hosts'] = ''

            mqtt_results[filename]['unique_topics'] = result['unique_topics']
            mqtt_results[filename]['number_unique_topics'] = len(result['unique_topics'])

        if os.path.isfile(f) and 'mqtt.txt' in files:

            result = iter(open(f, 'r'))

            vulnerable_endpoints = []

            first_time = True

            for line in result:

                if '[+] Server ' in line and first_time:
                    port = line.replace('[+] Server ', '').split(' is')[0].split(':')[1]
                    first_time = False

                    mqtt_results[filename]['port'] = port
                    

                if line == 'Vulnerable endpoints:\n':
                    line = next(result, None)
                    while 'Total number of vulnerable endpoints:' not in line:
                        vulnerable_endpoints.append(line.split('vuln: ')[1].replace('\']\n', ''))
                        line = next(result, None)                    

                    mqtt_results[filename]['vulnerabilities'] = vulnerable_endpoints
    
with open('./mqtt_parsed_2022.json', 'w') as output_file:
    json.dump(mqtt_results, output_file)
