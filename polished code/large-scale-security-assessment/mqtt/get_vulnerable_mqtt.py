import json
import pycountry_convert as pc

analysis = json.load(open('mqtt_total_2022.json', 'r'))
emails = json.load(open('email_addresses.json', 'r'))

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

for domain_name, endpoint in analysis.items():    

    e = {}
    if 'country' in endpoint:
        e['country'] = endpoint['country']
    if 'provider' in endpoint:
        e['provider'] = endpoint['provider']

    e['vulnerability_classes'] = {}

    check_vulnerable_endpoints(endpoint,domain_name,e)

    if e['vulnerability_classes'] == {}:
        pass
    else:
        if domain_name in emails and len(emails[domain_name]) > 0:
            e['emails'] = emails[domain_name]
        vulnerable_endpoints[domain_name] = e

json.dump(vulnerable_endpoints, open('vulnerable_2022.json', 'w'))