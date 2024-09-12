import os, json

directories = ['security-results/']

xmpp_results = {}
connection_results = {'success': 0, 'down': 0, 'closed': 0, 'filtered': 0}
start_tls = {'failed': 0, 'success': 0}

success = set()

for directory in directories:
    for endpoint in os.listdir(directory):
        if os.path.isdir(directory + endpoint):
            for file in os.listdir(os.path.join(directory, endpoint)):

                f = os.path.join(directory, endpoint, file)

                if 'xmpp.txt' in file:
                    result = iter(open(f, 'r'))

                    for line in result:
                        # if 'Host seems down' in line:
                        #     connection_results['down'] += 1
                        #     #xmpp_results[endpoint]['connection'] = 'failed'
                        #     break
                        if '5222/tcp' in line or '5269/tcp' in line:
                            if 'open' in line:
                        #         #xmpp_results[endpoint] = {}
                        #         # if endpoint in security_analysis:
                        #         #     xmpp_results[endpoint] = security_analysis[endpoint]
                        #         # if endpoint in general_analysis:
                        #         #     xmpp_results[endpoint]['provider'] = general_analysis[endpoint]['provider']
                        #         #     if len(general_analysis[endpoint]['countries']) > 0:
                        #         #         xmpp_results[endpoint]['country'] = general_analysis[endpoint]['countries'][0]
                                connection_results['success'] += 1
                                # xmpp_results[endpoint]['connection'] = 'success'
                                success.add(endpoint)
                            elif 'closed' in line:
                                connection_results['closed'] += 1
                                # xmpp_results[endpoint]['connection'] = 'closed'
                            elif 'filtered' in line:
                                connection_results['filtered'] += 1
                                # xmpp_results[endpoint]['connection'] = 'filtered'
                            break
                        if 'STARTTLS' in line:
                            if 'Failed' in line:
                                start_tls['failed'] += 1
                                #xmpp_results[endpoint]['STARTTLS'] = 'Failed'

                            else:
                                start_tls['success'] += 1
                                # xmpp_results[endpoint]['STARTTLS'] = 'Success'
                            break

print(success)
print(len(success))
print(connection_results)
