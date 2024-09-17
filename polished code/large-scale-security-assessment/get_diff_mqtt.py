import json

NEW_RUN = json.load(open('2024/mqtt/mqtt_parsed_2024.json', 'r'))
OLD_RUN = json.load(open('mqtt_diff_2023.json', 'r'))

vulnerable_endpoints = {}

excluded_versions = ['Development Snapshot', '{\"version\":\"unknown\"}', '{\"version\":\"107\"}', '{\"msg\":\"Subscription succeeded\",\"sn\":\"ReplyServer\",\"name\":\"AutoReply\",\"ply\":5}']

def add_element_to_object(element, object, endpoint):
    if element in endpoint:
        if endpoint[element] not in object:
            object[endpoint[element]] = 1
        else:
            object[endpoint[element]] += 1

def check_vulnerable_endpoints(e, d, v):
    if "vulnerabilities" in e and len(e['vulnerabilities']) > 0:
        v['vulnerability_classes']['DoS'] = {}
        v['vulnerability_classes']['DoS']['scanning_technique'] = 'cotopaxi_testing_for_known_vulnerabilities'
        v['vulnerability_classes']['DoS']['CVEs'] = []
        for vuln in e['vulnerabilities']:
            if "CONTIKI" in vuln:
                v['vulnerability_classes']['DoS']['CVEs'].append('CVE-2018-19417')
            if "FLUENTBIT" in vuln:
                v['vulnerability_classes']['DoS']['CVEs'].append('CVE-2019-9749')

    if "number_unique_topics" in e and e['number_unique_topics'] > 0:
        v['vulnerability_classes']['information_leakage'] = []
        topic_enumeration = {}
        topic_enumeration['scanning_technique'] = 'topic_enumeration'
        topic_enumeration['number_of_collected_topics'] = e['number_unique_topics']
        v['vulnerability_classes']['information_leakage'].append(topic_enumeration)

    if "connected_hosts" in e and e['connected_hosts'] != '':
        connected_clients = {}
        connected_clients['scanning_technique'] = 'extract_number_of_connected_clients'
        connected_clients['number_of_connected_clients'] = e['connected_hosts']
        if 'information_leakage' in v['vulnerability_classes']:
            v['vulnerability_classes']['information_leakage'].append(connected_clients)
        else:
            v['vulnerability_classes']['information_leakage'] = [connected_clients]

    if ("version" in e and e['version'] != '' and e['version'] not in excluded_versions):
        server_version = {}
        server_version['scanning_technique'] = 'extract_server_version'
        server_version['CVEs'] = []
        version = e['version'].replace('mosquitto version ', '')
        if version <= '1.4.15' and version >= '1.0':
            server_version['CVEs'].append('CVE-2017-7655')
        if version <= '1.5.5':
            server_version['CVEs'].append('CVE-2018-12550')
            server_version['CVEs'].append('CVE-2018-12551')

        if 'information_leakage' in v['vulnerability_classes']:
            v['vulnerability_classes']['information_leakage'].append(server_version)
        else:
            v['vulnerability_classes']['information_leakage'] = [server_version]

updated_res = {}
successful_connection = 0

for backend, values in OLD_RUN.items():  

    ## remove some data to avoid the file being too difficult to parse
    try:
        del OLD_RUN[backend]['country']
        del OLD_RUN[backend]['emails']
    except:
        pass


    if backend in NEW_RUN:
        if "connection" in NEW_RUN[backend] and NEW_RUN[backend]["connection"] == 'success':

            successful_connection += 1

            OLD_RUN[backend]['status_jan2024'] = 'online'

            new_run_result = {}
            new_run_result['vulnerability_classes'] = {}
            check_vulnerable_endpoints(NEW_RUN[backend], backend, new_run_result)

            if (('update_sep_2023' in values and values['update_sep_2023'] == new_run_result['vulnerability_classes']) or ('vulnerability_classes' in values and values['vulnerability_classes'] == new_run_result['vulnerability_classes'])):
                print('OK')
            else:
                OLD_RUN[backend]['update_jan2024'] = new_run_result['vulnerability_classes']
                print('different')

                # print(new_run_result['vulnerability_classes'])
                # print(values['vulnerability_classes'])
        
        else:
            OLD_RUN[backend]['status_jan2024'] = 'offline'
            print('offline')
    else:
        OLD_RUN[backend]['status_jan2024'] = 'offline'
        print('offline')

    updated_res[backend] = OLD_RUN[backend]

print(successful_connection)
json.dump(updated_res, open('mqtt_diff_2024.json', 'w'))