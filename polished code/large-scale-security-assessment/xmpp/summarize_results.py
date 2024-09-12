import json
from statistics import mean, stdev

xmpp_data = json.load(open('xmpp_parsed_2022.json', 'r'))

result = {}
result['ports'] = {}
result['capabilities'] = {}
result['features'] = {}
result['compression_methods'] = {}
result['auth_mechanisms'] = {}
result['server_names'] = {}
result['langs'] = {}
result['versions'] = {}
result['errors'] = {}

for host, element in xmpp_data.items():

    for key, value in element.items():

        if key != 'credentials':
            if key in result['ports']:
                result['ports'][key] += 1
            else:
                result['ports'][key] = 1
            
            if 'server_name' in value:
                if value['server_name'] in result['server_names']:
                    result['server_names'][value['server_name']] += 1
                else:
                    result['server_names'][value['server_name']] = 1

            if 'lang' in value:
                if value['lang'] in result['langs']:
                    result['langs'][value['lang']] += 1
                else:
                    result['langs'][value['lang']] = 1

            if 'version' in value:
                if value['version'].replace('|_version:', '') in result['versions']:
                    result['versions'][value['version'].replace('|_version:', '')] += 1
                else:
                    result['versions'][value['version'].replace('|_version:', '')] = 1
                
            if 'errors' in value and len(value['errors']) > 0:
                error = ''
                for e in value['errors']:
                    error += e
                if error in result['errors']:
                    result['errors'][error] += 1
                else:
                    result['errors'][error] = 1

            if 'features' in value and len(value['features']) > 0:
                for feature in value['features']:
                    if feature in result['features']:
                        result['features'][feature] += 1
                    else:
                        result['features'][feature] = 1

            if 'capabilities' in value and len(value['capabilities']) > 0:
                for capability in value['capabilities']:
                    if capability in result['capabilities']:
                        result['capabilities'][capability] += 1
                    else:
                        result['capabilities'][capability] = 1

            if 'compression_methods' in value and len(value['compression_methods']) > 0:
                for compression_method in value['compression_methods']:
                    if compression_method in result['compression_methods']:
                        result['compression_methods'][compression_method] += 1
                    else:
                        result['compression_methods'][compression_method] = 1

            if 'auth_mechanisms' in value and len(value['auth_mechanisms']) > 0:
                for auth_mechanism in value['auth_mechanisms']:
                    if auth_mechanism in result['auth_mechanisms']:
                        result['auth_mechanisms'][auth_mechanism] += 1
                    else:
                        result['auth_mechanisms'][auth_mechanism] = 1
            
with open('test.json', 'w') as output_file:
    json.dump(result, output_file)