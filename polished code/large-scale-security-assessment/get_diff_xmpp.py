import json

NEW_RUN = json.load(open('2024/xmpp/xmpp_parsed_2024.json', 'r'))
OLD_RUN = json.load(open('xmpp_diff_2023.json', 'r'))

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

    if 'connection' in val and val['connection'] == 'failed':
        return -1
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
    
    return 1

def print_obj(text, obj):
    tmp_obj = {}
    tmp_obj['other'] = 0
    for k, v in obj.items():
        if v > 4:
            tmp_obj[k] = v
        else:
            tmp_obj['other'] += 1
    print(text, tmp_obj)

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

        new_run_result = {}
        new_run_result['vulnerability_classes'] = {}

        connection_statuses = set()

        for port, port_values in NEW_RUN[backend].items():
            connection_status = check_vulnerable_endpoints(port_values, NEW_RUN[backend], backend, new_run_result)
            connection_statuses.add(connection_status)
    
        print(connection_statuses)

        if len(connection_statuses) == 1 and list(connection_statuses)[0] == -1:
            OLD_RUN[backend]['status_jan2024'] = 'offline'
        else:
            OLD_RUN[backend]['status_jan2024'] = 'online'
            successful_connection += 1
            # print(new_run_result['vulnerability_classes'])
            if ('vulnerability_classes' in values and values['vulnerability_classes'] == new_run_result['vulnerability_classes']) or ('update_sep_2023' in values and values['update_sep_2023'] == new_run_result['vulnerability_classes']):   
                pass
            else:
                OLD_RUN[backend]['update_jan2024'] = new_run_result['vulnerability_classes']

    else:
        OLD_RUN[backend]['status_jan2024'] = 'offline'

    updated_res[backend] = OLD_RUN[backend]

print(successful_connection)
json.dump(updated_res, open('xmpp_diff_2024.json', 'w'))