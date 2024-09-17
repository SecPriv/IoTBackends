import json

NEW_RUN = json.load(open('2024/coap/coap_parsed_2024.json', 'r'))
RESOURCES = json.load(open('2024/coap/active_endpoints.json', 'r'))
OLD_RUN = json.load(open('coap_diff_2023.json', 'r'))

vulnerable_endpoints = {}

def add_element_to_object(element, object, endpoint):
    if element in endpoint:
        if endpoint[element] not in object:
            object[endpoint[element]] = 1
        else:
            object[endpoint[element]] += 1

def check_vulnerable_endpoints(e, d, v):
    if 'iotivity_AF' in e and float(e['iotivity_AF']) >= 100:
        v['vulnerability_classes']['amplification_vulnerability'] = {}
        v['vulnerability_classes']['amplification_vulnerability']['CVEs'] = ['CVE-2019-9750']
        v['vulnerability_classes']['amplification_vulnerability']['scanning_technique'] = 'cotopaxi_testing_for_known_vulnerabilities'

        
    if 'zyxel_AF' in e and float(e['zyxel_AF']) >= 100:
        if 'amplification_vulnerability' not in v['vulnerability_classes']:
            v['vulnerability_classes']['amplification_vulnerability'] = {}
            v['vulnerability_classes']['amplification_vulnerability']['CVEs'] = ['ZYXEL_000']
            v['vulnerability_classes']['amplification_vulnerability']['scanning_technique'] = 'cotopaxi_testing_for_known_vulnerabilities'
        else:
            v['vulnerability_classes']['amplification_vulnerability']['CVEs'].append('ZYXEL_000')

    if 'vulnerabilities' in e and len(e['vulnerabilities']) > 0:
        for vu in e['vulnerabilities']:
            if "COAPTHON" in vu:
                v['vulnerability_classes']['DoS'] = {}
                v['vulnerability_classes']['DoS']['CVE'] = 'CVE-2018-12679'
                v['vulnerability_classes']['DoS']['scanning_technique'] = 'cotopaxi_testing_for_known_vulnerabilities'

    if d in RESOURCES:
        count_resources = 0
        for name, rc in RESOURCES[d].items():
            if rc == '2_05':
                count_resources += 1
        if count_resources != 0:
            v['vulnerability_classes']['information_leakage'] = []
            resource_exposure = {}
            resource_exposure['number_of_exposed_resources'] = count_resources
            resource_exposure['scanning_technique'] = 'resource_enumeration_via_HEAD'
            v['vulnerability_classes']['information_leakage'].append(resource_exposure)
                

    if 'protocol' in e and e['protocol'] != '':
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
    print(text, tmp_obj)

updated_res = {}

success = 0

for backend, values in OLD_RUN.items():  

    ## remove some data to avoid the file being too difficult to parse
    try:
        del OLD_RUN[backend]['country']
        del OLD_RUN[backend]['emails']
    except:
        pass

    if backend in NEW_RUN:
        if "connection_status" in NEW_RUN[backend] and NEW_RUN[backend]["connection_status"] == 'success':

            success += 1

            OLD_RUN[backend]['status_jan2024'] = 'online'          

            new_run_result = {}
            new_run_result['vulnerability_classes'] = {}
            check_vulnerable_endpoints(NEW_RUN[backend], backend, new_run_result)

            if (('update_sep_2023' in values and values['update_sep_2023'] == new_run_result['vulnerability_classes']) or ('vulnerability_classes' in values and values['vulnerability_classes'] == new_run_result['vulnerability_classes'])):
                pass
                # print('OK\n\n')
            else:
                print('different')
                OLD_RUN[backend]['update_jan2024'] = new_run_result['vulnerability_classes']

                # print(new_run_result['vulnerability_classes'])
                # if 'update_sep_2023' in OLD_RUN:
                #     print(OLD_RUN['update_sep_2023'])
                # print(values['vulnerability_classes'])
        
        else:
            OLD_RUN[backend]['status_jan2024'] = 'offline'
            # print('offline\n\n')
    else:
        OLD_RUN[backend]['status_jan2024'] = 'offline'
        # print('offline\n\n')
    
    updated_res[backend] = OLD_RUN[backend]
 
    # print('\n\n')

print(success)
json.dump(updated_res, open('coap_diff_2024.json', 'w'))