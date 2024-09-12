import os, re, json

def parse_nmap_scan(result, times):

    count_times = 0
    port = times
    dict_result = {}

    for line in result:

        if 'Starting Nmap 7.80' in line:
            if count_times >= times:
                break
            else:
                dict_result = {}
                count_times += 1

        if 'xmpp-client' in line or 'xmpp-server' in line:
            port = line.split('/')[0]

        # if 'Host seems down' in line:
        #     dict_result['connection'] = 'down'
        #     #xmpp_results[endpoint]['connection'] = 'failed'
        
        # if '5222/tcp' in line or '5269/tcp' in line:
        #     if 'open' in line:
        #         dict_result['connection'] = 'success'
        #     else:
        #         dict_result['connection'] = 'failed'

        if 'info:' in line:

            while 'Nmap done' not in line and '|   pre_tls:' not in line:

                if 'lang:' in line:
                    dict_result['lang'] = line.strip('\n').replace('|       lang:', '').replace(' ', '')
                    line = next(result, None)

                elif 'server name:' in line:
                    dict_result['server_name'] = line.strip('\n').replace('|       server name:', '').replace(' ', '')
                    line = next(result, None)

                elif 'version:' in line:
                    dict_result['version'] = line.strip('\n').replace('|       version:', '').replace(' ', '')
                    line = next(result, None)

                elif 'features:' in line:
                    features = []
                    line = next(result, None)
                    while not re.search('\|\s\s\s\s\s[a-zA-Z].*', line) and line != '\n' and line != '| \n' and not re.search('\|\s\s\s[a-zA-Z].*', line):
                        features.append(line.strip('\n').replace('|       ', '').replace('|_      ', ''))
                        line = next(result, None)
                    dict_result['features'] = features

                elif 'compression_methods:' in line:
                    features = []
                    line = next(result, None)
                    while not re.search('\|\s\s\s\s\s[a-zA-Z].*', line) and line != '\n' and line != '| \n' and not re.search('\|\s\s\s[a-zA-Z].*', line):
                        features.append(line.strip('\n').strip('|       '))
                        line = next(result, None)
                    dict_result['compression_methods'] = features

                elif 'capabilities:' in line:
                    features = []
                    line = next(result, None)
                    while not re.search('\|\s\s\s\s\s[a-zA-Z].*', line) and line != '\n' and line != '| \n' and not re.search('\|\s\s\s[a-zA-Z].*', line):
                        features.append(line.strip('\n').strip('|       '))
                        line = next(result, None)
                    dict_result['capabilities'] = features

                elif 'auth_mechanisms:' in line:
                    features = []
                    line = next(result, None)
                    while not re.search('\|\s\s\s\s\s[a-zA-Z].*', line) and line != '\n' and line != '| \n' and not re.search('\|\s\s\s[a-zA-Z].*', line):
                        features.append(line.strip('\n').strip('|       '))
                        line = next(result, None)
                    dict_result['auth_mechanisms'] = features   

                elif 'errors:' in line:
                    errors = []
                    line = next(result, None)
                    while not re.search('\|\s\s\s\s\s[a-zA-Z].*', line) and line != '\n' and line != '| \n' and not re.search('\|\s\s\s[a-zA-Z].*', line):
                        errors.append(line.strip('\n').replace('|       ', '').replace('|_      ', ''))
                        line = next(result, None)
                    dict_result['errors'] = errors      

                else:
                    line = next(result, None)   
 
    return dict_result, port

directory = 'security-results/'
xmpp_results = {}

for item in os.listdir(directory):
    if os.path.isdir(directory + item):
        for file in os.listdir(os.path.join(directory, item)):

            f = os.path.join(directory, item, file)

            if 'xmpp.txt' in file:
                xmpp_results[item] = {}

                print(item)

                result = iter(open(f, 'r'))
                port_1, p_1 = parse_nmap_scan(result, 1)

                result = iter(open(f, 'r'))
                port_2, p_2 = parse_nmap_scan(result, 2)

                if port_1 != {} and port_2 != {}:
                    if p_1 == p_2:
                        xmpp_results[item][p_1] = port_1
                    else:
                        xmpp_results[item][p_1] = port_1
                        xmpp_results[item][p_2] = port_2
                elif port_1 != {}:
                    xmpp_results[item][p_1] = port_1
                elif port_2 != {}:
                    xmpp_results[item][p_2] = port_2

with open('xmpp_parsed_2022.json', 'w') as output_file:
    json.dump(xmpp_results, output_file)