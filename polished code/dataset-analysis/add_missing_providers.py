import json, socket, csv, sys
from netaddr import IPNetwork, IPAddress

# CAN BE mqtt, coap OR xmpp
protocol = sys.argv[1]
print('Analyzing', protocol)

file = 'parsed-shodan-results/general_analysis_' + protocol + '.json'
general_analysis = json.load(open(file, 'r'))

oracle_ranges = json.load(open('ip-ranges-cloud-providers/oracle.json', 'r'))
digital_ocean_ranges = csv.reader(open('ip-ranges-cloud-providers/digitalocean.csv'), delimiter=',')
yandex_ranges = csv.reader(open('ip-ranges-cloud-providers/yandex.csv'), delimiter=',')
ibm_ranges = json.load(open('ip-ranges-cloud-providers/ibm.json', 'r'))
salesforce_ranges = json.load(open('ip-ranges-cloud-providers/salesforce.json', 'r'))

count_oracle = 0
count_digital = 0
count_yandex = 0
count_ibm = 0
count_salesforce = 0

def check_oracle(e):
    for region in oracle_ranges['regions']:
        for cidr in region['cidrs']:
            ip_range = cidr['cidr']
            if IPAddress(e) in IPNetwork(ip_range):
                return True

def check_digital_ocean(e):
    for row in digital_ocean_ranges:
        if IPAddress(e) in IPNetwork(row[0]):
            return True

def check_yandex(e):
    for row in yandex_ranges:
        if IPAddress(e) in IPNetwork(row[1]):
            return True

def check_ibm(e):
    for range in ibm_ranges:
        if IPAddress(e) in IPNetwork(range):
            return True

def check_salesforce(e):
    for range in salesforce_ranges:
        if IPAddress(e) in IPNetwork(range):
            return True

def check_new_providers(e):

    if check_oracle(e):
        return 'oracle'
    if check_digital_ocean(e):
        return 'digitalocean'
    if check_yandex(e):
        return 'yandex'
    if check_ibm(e):
        return 'ibm'
    if check_salesforce(e):
        return 'salesforce'

    return ''

updated_analysis = []

for endpoint in general_analysis:
    if 'provider' in endpoint and endpoint['provider'] == 'unknown':
        try:
            provider = check_new_providers(endpoint['ip'])
            if provider == 'oracle':
                count_oracle += 1
                endpoint['provider'] = 'oracle'
            if provider == 'digitalocean':
                count_digital += 1
                endpoint['provider'] = 'digitalocean'
            if provider == 'yandex':
                count_yandex += 1
                endpoint['provider'] = 'yandex'
            if provider == 'ibm':
                count_ibm += 1
                endpoint['provider'] = 'ibm'
            if provider == 'salesforce':
                count_salesforce += 1
                endpoint['provider'] = 'salesforce'
        except:
            pass
    
    updated_analysis.append(endpoint)

print('Oracle endpoints: ', count_oracle)
print('Digital Ocean endpoints: ', count_digital)
print('Yandex endpoints: ', count_yandex)
print('IBM endpoints: ', count_ibm)
print('Salesforce endpoints: ', count_salesforce)

json.dump(updated_analysis, open(file, 'w'))