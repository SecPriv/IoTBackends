import os, json

connection_success = json.load(open('parsed/coap_connection.json', 'r'))

g_1 = json.load(open('../../dataset-analysis/parsed-shodan-results/general_analysis_coap.json', 'r'))
s_1 = json.load(open('coap_parsed_2022.json', 'r'))
endpoints = json.load(open('active_endpoints.json', 'r'))

coap_results = {}

counter = 0

#iterate over all the subfolders
for endpoint_port, value in connection_success.items():

    endpoint = endpoint_port.split(':')[0]

    counter += 1

    if counter % 1000 == 0:
        print('Analyzed', str(counter), 'endpoints')

    if 'connection_status' not in value or value['connection_status'] == 'success':
        coap_results[endpoint] = {}
        if endpoint_port in s_1:
            coap_results[endpoint] = s_1[endpoint_port]
        if endpoint in g_1:
            coap_results[endpoint]['provider'] = g_1[endpoint]['provider']
            if len(g_1[endpoint]['countries']) > 0:
                coap_results[endpoint]['country'] = g_1[endpoint]['countries'][0]

        if 'zyxel_AF' in value:
            coap_results[endpoint]['zyxel_AF'] = value['zyxel_AF']

        if 'iotivity_AF' in value:
            coap_results[endpoint]['iotivity_AF'] = value['iotivity_AF']

        if endpoint in endpoints:
            coap_results[endpoint]['active_endpoints'] = endpoints[endpoint]

    #iterate over sub-subfolders
    # for files in os.listdir(os.path.join(directory, filename)):

    #     f = os.path.join(directory, filename, files)

    #     if os.path.isfile(f) and 'cotopaxi.txt' in files:
    #         result = iter(open(f, 'r'))

    #         first_time = True

    #         for line in result:

                # if '[.] Host ' in line and first_time:
                #     ip_port = line.replace('[.] Host ', '').split('is')[0].replace(' ', '')
                #     first_time = False
                #     coap_results[filename] = {}

                # if 'is dead before test' in line:
                #     coap_results[ip_port]['connection_status'] = 'not responding'
                #     break
                # if 'Cannot resolve hostname' in line: 
                #     coap_results[ip_port]['connection_status'] = 'not resolving'
                #     break
                # if 'is alive after test' in line:
                #     coap_results[filename] = {}
                #     #coap_results[ip_port]['connection_status'] = 'success'
                #     if filename in s_1:
                #         coap_results[filename] = s_1[filename]
                #     if filename in g_1:
                #         coap_results[filename]['provider'] = g_1[filename]['provider']
                #         if len(g_1[filename]['countries']) > 0:
                #             coap_results[filename]['country'] = g_1[filename]['countries'][0]
                
                
                # if 'IOTIVITY_000' in line:
                #     while 'ZYXEL_000' not in line:
                #         line = next(result, None)
                #         if 'amplyfing traffic' in line:
                #             coap_results[filename]['iotivity_AF'] = line.split('FACTOR: ')[-1].replace('%\n', '')

                # if 'ZYXEL_000' in line:
                #     while 'amplyfing traffic! AMPLIFICATION' not in line:
                #         line = next(result, None)
                #     if 'amplyfing traffic' in line:
                #         coap_results[filename]['zyxel_AF'] = line.split('FACTOR: ')[-1].replace('%\n', '')
                #         break
    
with open('../coap_total_2022.json', 'w') as output_file:
    json.dump(coap_results, output_file)