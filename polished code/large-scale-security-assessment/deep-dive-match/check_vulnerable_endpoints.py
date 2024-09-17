import json

matches = json.load(open('mqtt_domain_name_match.json', 'r'))
full_mqtt = json.load(open('../mqtt/vulnerable_2022.json', 'r'))

count_successful_connections = 0
count_vulnerable = 0

already_analyzed = set()
excluded_versions = ['Development Snapshot', '{\"version\":\"unknown\"}', '{\"version\":\"107\"}', '{\"msg\":\"Subscription succeeded\",\"sn\":\"ReplyServer\",\"name\":\"AutoReply\",\"ply\":5}']

def count_vulnerable_endpoints(e, d):
    if d not in already_analyzed:
        already_analyzed.add(d)

        if "vulnerabilities" in e and len(e['vulnerabilities']) > 0:
            for v in e['vulnerabilities']:
                if "CONTIKI" in v:
                    return True
                if "FLUENTBIT" in v:
                    return True

        if "username" in e and e['username'] != "":
            return True

        if "number_unique_topics" in e and e['number_unique_topics'] > 0:
            return True

        if "connected_hosts" in e and e['connected_hosts'] != '':
            return True


        if "version" in e and e['version'] != '' and e['version'] not in excluded_versions:
            updated_version = e['version'].replace('mosquitto version ', '').replace('smopush version ','').replace('{\"version\":\"', '').replace('\"}', '')
            if updated_version < '1.5':
                return True
    return False    

connection_statuses = set()

for e, m in matches.items():
    if m[0] in full_mqtt:
        print(full_mqtt[m[0]])
        connection_statuses.add(full_mqtt[m[0]]['connection'])
        if count_vulnerable_endpoints(full_mqtt[m[0]], m[0]):
            count_vulnerable += 1
        count_successful_connections += 1
        continue

print(count_successful_connections)
print(count_vulnerable)

print(connection_statuses)
