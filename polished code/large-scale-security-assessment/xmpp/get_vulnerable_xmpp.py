import json

analysis = json.load(open('xmpp_total_2022.json', 'r'))
emails = json.load(open('email_addresses.json', 'r'))

vulnerable_endpoints = {}

WEAK_AUTH_MECHANISMS = ['PLAIN', 'ANONYMOUS', 'CRAM-MD5', 'DIGEST-MD5']

already_analyzed = set()

def add_element_to_object(element, object, endpoint):
    if element in endpoint:
        if endpoint[element] not in object:
            object[endpoint[element]] = 1
        else:
            object[endpoint[element]] += 1

def check_vulnerable_endpoints(val, e, d, v):
    if 'auth_mechanisms' in val:
        for am in val['auth_mechanisms']:
            if am in WEAK_AUTH_MECHANISMS:
                if 'weak_authentication' not in v['vulnerability_classes']:
                    v['vulnerability_classes']['weak_authentication'] = []
                if len(v['vulnerability_classes']['weak_authentication']) == 0:
                    weak_auth = {}
                    weak_auth['scanning_technique'] = 'extract_supported_auth_mechanisms'
                    weak_auth['supported_weak_mechanisms'] = [am]
                    v['vulnerability_classes']['weak_authentication'].append(weak_auth)
                else:
                   v['vulnerability_classes']['weak_authentication'][0]['supported_weak_mechanisms'].append(am)

    if ('features' in val and len(val['features']) > 0) or ('capabilities' in val and len(val['capabilities']) > 0)  or ('lang' in val and val['lang'] != ''):
        feature_extraction = {"scanning_technique": "extract_supported_features_and_capabilities_and_compression_methods"}
        if 'information_leakage' in v['vulnerability_classes']:
            if feature_extraction in v['vulnerability_classes']['information_leakage']:
                v['vulnerability_classes']['information_leakage'] = [feature_extraction]
        elif 'information_leakage' not in v['vulnerability_classes']:
            v['vulnerability_classes']['information_leakage'] = [feature_extraction]
    
    if ('server_name' in val and val['server_name'] != '') or ('version' in val and val['version'] != ''):
        if 'information_leakage' not in v['vulnerability_classes']:
            v['vulnerability_classes']['information_leakage'] = [{"scanning_technique": "extract_server_version"}]
        else:
            v['vulnerability_classes']['information_leakage'].append({"scanning_technique": "extract_server_version"})

    if 'credentials' in e and len(e['credentials']) > 0:
        default_creds = {"scanning_technique": "connect_with_known_credentials"}
        if 'weak_authentication' in v['vulnerability_classes'] and default_creds not in v['vulnerability_classes']['weak_authentication']:
            v['vulnerability_classes']['weak_authentication'].append(default_creds)
        else: 
            v['vulnerability_classes']['weak_authentication'] = [default_creds]


def print_obj(text, obj):
    tmp_obj = {}
    tmp_obj['other'] = 0
    for k, v in obj.items():
        if v > 4:
            tmp_obj[k] = v
        else:
            tmp_obj['other'] += 1
    print(text, tmp_obj)

for domain_name, endpoint in analysis.items():    

    if domain_name not in already_analyzed:

        e = {}
        if 'country' in endpoint:
            e['country'] = endpoint['country']
        if 'provider' in endpoint:
            e['provider'] = endpoint['provider']

        e['vulnerability_classes'] = {}

        for port, values in endpoint.items():
            check_vulnerable_endpoints(values, endpoint,domain_name,e)

        if e['vulnerability_classes'] == {}:
            pass
        else:
            if domain_name in emails and len(emails[domain_name]) > 0:
                e['emails'] = emails[domain_name]
            vulnerable_endpoints[domain_name] = e
        
        already_analyzed.add(domain_name)

json.dump(vulnerable_endpoints, open('vulnerable_2022.json', 'w'))