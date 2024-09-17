import json

analysis = json.load(open('coap_total_2022.json', 'r'))
resources = json.load(open('active_endpoints.json', 'r'))

emails = json.load(open('email_addresses.json', 'r'))

vulnerable_endpoints = {}

def add_element_to_object(element, object, endpoint):
    if element in endpoint:
        if endpoint[element] not in object:
            object[endpoint[element]] = 1
        else:
            object[endpoint[element]] += 1

def check_vulnerable_endpoints(e, d, v):
    if float(e['iotivity_AF']) >= 100:
        v['vulnerability_classes']['amplification_vulnerability'] = {}
        v['vulnerability_classes']['amplification_vulnerability']['CVEs'] = ['CVE-2019-9750']
        v['vulnerability_classes']['amplification_vulnerability']['scanning_technique'] = 'cotopaxi_testing_for_known_vulnerabilities'

        
    if float(e['zyxel_AF']) >= 100:
        if 'amplification_vulnerability' not in v['vulnerability_classes']:
            v['vulnerability_classes']['amplification_vulnerability'] = {}
            v['vulnerability_classes']['amplification_vulnerability']['CVEs'] = ['ZYXEL_000']
            v['vulnerability_classes']['amplification_vulnerability']['scanning_technique'] = 'cotopaxi_testing_for_known_vulnerabilities'
        else:
            v['vulnerability_classes']['amplification_vulnerability']['CVEs'].append('ZYXEL_000')

    if len(e['vulnerabilities']) > 0:
        for vu in e['vulnerabilities']:
            if "COAPTHON" in vu:
                v['vulnerability_classes']['DoS'] = {}
                v['vulnerability_classes']['DoS']['CVE'] = 'CVE-2018-12679'
                v['vulnerability_classes']['DoS']['scanning_technique'] = 'cotopaxi_testing_for_known_vulnerabilities'

    if d in resources:
        count_resources = 0
        for name, rc in resources[d].items():
            if rc == '2_05':
                count_resources += 1
        if count_resources != 0:
            v['vulnerability_classes']['information_leakage'] = []
            resource_exposure = {}
            resource_exposure['number_of_exposed_resources'] = count_resources
            resource_exposure['scanning_technique'] = 'resource_enumeration_via_HEAD'
            v['vulnerability_classes']['information_leakage'].append(resource_exposure)
                

    if e['protocol'] != '':
        server_fingerprint = {"scanning_technique": "cotopaxi_extract_server_version"}
        if 'information_leakage' in v['vulnerability_classes']:
            v['vulnerability_classes']['information_leakage'].append(server_fingerprint)
        else:
            v['vulnerability_classes']['information_leakage'] = [server_fingerprint]

def print_obj(text, obj):
    tmp_obj = {}
    tmp_obj['other'] = 0
    for k, v in obj.items():
        if v > 4:
            tmp_obj[k] = v
        else:
            tmp_obj['other'] += 1

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