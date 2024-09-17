import json
from packaging import version

excluded_versions = ['Development Snapshot', '{\"version\":\"unknown\"}', '{\"version\":\"107\"}', '{\"msg\":\"Subscription succeeded\",\"sn\":\"ReplyServer\",\"name\":\"AutoReply\",\"ply\":5}']

def get_version_2022():

    VERSIONS_2022 = {}
    SHODAN_2022 = json.load(open('mqtt/mqtt_parsed_2022.json', 'r'))

    for backend, values in SHODAN_2022.items():
        if 'version' in values and values['version'] != '' and values['version'] not in excluded_versions:
            VERSIONS_2022[backend] = values['version']
    
    json.dump(VERSIONS_2022, open('mqtt_versions_2022.json', 'w+'))

def get_version_2023():

    VERSIONS_2023 = {}
    SHODAN_2023 = json.load(open('2023/mqtt/mqtt_parsed_2023.json', 'r'))

    for backend, values in SHODAN_2023.items():
        if 'version' in values and values['version'] != '' and values['version'] not in excluded_versions:
            VERSIONS_2023[backend] = values['version']
    
    json.dump(VERSIONS_2023, open('mqtt_versions_2023.json', 'w+'))

def get_better_worse_versions():

    better_performing = set()
    worse_performing = set()
    equal_performing = set()

    V_2022 = json.load(open('mqtt_versions_2022.json', 'r'))
    V_2023 = json.load(open('mqtt_versions_2023.json', 'r'))

    for backend, v in V_2022.items():
        if backend in V_2023:
            if version.parse(v) < version.parse(V_2023[backend]):
                better_performing.add(backend)
            elif version.parse(v) == version.parse(V_2023[backend]):
                equal_performing.add(backend)
            elif version.parse(v) > version.parse(V_2023[backend]):
                worse_performing.add(backend)
            
    print('Better', str(len(better_performing)))
    print('Worse', str(len(worse_performing)))
    print('equal', str(len(equal_performing)))

get_version_2022()
get_version_2023()

get_better_worse_versions()