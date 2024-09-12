import os, json

directory = './security-results/'

coap_results = {}

counter = 0

#iterate over all the subfolders
for filename in os.listdir(directory):

    counter += 1

    if counter % 1000 == 0:
        print('Analyzed', str(counter), 'files')

    #iterate over sub-subfolders
    for files in os.listdir(os.path.join(directory, filename)):

        f = os.path.join(directory, filename, files)

        if os.path.isfile(f) and 'cotopaxi.txt' in files:
            result = iter(open(f, 'r'))

            adopted_protocol = ''
            active_endpoints = []
            vulnerable_endpoints = []

            first_time = True

            for line in result:

                if '[.] Host ' in line and first_time:
                    first_time = False
                    coap_results[filename] = {}

                if 'is dead before test' in line:
                    coap_results[filename]['connection_status'] = 'not responding'
                    break
                if 'Cannot resolve hostname' in line: 
                    coap_results[filename]['connection_status'] = 'not resolving'
                    break
                if 'is alive after test' in line:
                    coap_results[filename]['connection_status'] = 'success'
                
                
                if 'IOTIVITY_000' in line:
                    while 'ZYXEL_000' not in line:
                        line = next(result, None)
                        if 'amplyfing traffic' in line:
                            coap_results[filename]['iotivity_AF'] = line.split('FACTOR: ')[-1].replace('%\n', '')

                if 'ZYXEL_000' in line:
                    while 'amplyfing traffic! AMPLIFICATION' not in line:
                        line = next(result, None)
                    if 'amplyfing traffic' in line:
                        coap_results[filename]['zyxel_AF'] = line.split('FACTOR: ')[-1].replace('%\n', '')

                if line == 'Identified:\n':
                    line = next(result, None)
                    while 'Total number of identified:' not in line:
                        adopted_protocol = line.split('is using')[1].replace('\']\n', '').replace(' ','')
                        line = next(result, None)

                    coap_results[filename]['protocol'] = adopted_protocol

                if 'Vulnerable endpoints:' in line:
                    line = next(result, None)
                    while 'Total number of vulnerable endpoints:' not in line:
                        if 'COAPTHON_000' in line: 
                            vulnerable_endpoints.append('COAPTHON')
                        if 'ZYXEL_000' in line:
                            vulnerable_endpoints.append('ZYXEL')
                        if 'IOTIVITY_000' in line:
                            vulnerable_endpoints.append('IOTIVITY')
                        line = next(result, None)                    
                    print(vulnerable_endpoints, '\n\n')
                    coap_results[filename]['vulnerabilities'] = vulnerable_endpoints
    
with open('./coap_parsed_2022.json', 'w') as output_file:
    json.dump(coap_results, output_file)