import json, os, sys

base_folder = 'security-results/'

coap_result = {}

count = 0

for endpoint in os.listdir(base_folder):

    count += 1

    if count % 1000 == 0:
        print("%d endpoints analyzed"%(count))

    for files in os.listdir(base_folder + endpoint):
        file = base_folder + endpoint + '/' + files

        if 'cotopaxi' in file:
            result = iter(open(file, 'r'))

            resources = {}

            for line in result:
                if '[+] Url' in line:
                    code = line.split('|')[3]
                    resource = line.split('|')[1] 

                    resources[resource] = code

            if resources != {}:
                coap_result[endpoint] =  resources

json.dump(coap_result, open('active_endpoints.json', 'w'))