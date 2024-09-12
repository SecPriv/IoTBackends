import json, sys
from netaddr import IPNetwork, IPAddress

def custom_append(item, list):
    if item not in list:
        list.append(item)

#load AWS IP ranges
aws_ranges = json.load(open('./ip-ranges-cloud-providers/aws.json', 'r'))

def check_ip_aws(ip):
    for range in aws_ranges['prefixes']:
        if IPAddress(ip) in IPNetwork(range['ip_prefix']):
            return True
    return False

#load Google IP ranges
google_ranges = json.load(open('./ip-ranges-cloud-providers/google.json', 'r'))
google_cloud_ranges = json.load(open('./ip-ranges-cloud-providers/google-cloud.json', 'r'))

def check_ip_google(ranges, ip):
    for range in ranges['prefixes']:
        try:
            if IPAddress(ip) in IPNetwork(range['ipv4Prefix']):
                return True
        except:
            pass
    return False

#load Azure IP ranges
azure_ranges = json.load(open('./ip-ranges-cloud-providers/azure.json', 'r'))

def check_ip_azure(ip):
    for item in azure_ranges['values']:
        for range in item['properties']['addressPrefixes']:
            if IPAddress(ip) in IPNetwork(range):
                return True
    return False

#load Cloudflare IP ranges
cloudflare_ranges = json.load(open('./ip-ranges-cloud-providers/cloudflare.json', 'r'))

def check_ip_cloudflare(ip):
    for range in cloudflare_ranges:
        if IPAddress(ip) in IPNetwork(range):
            return True
    return False

#load Alibaba IP ranges
alibaba_ranges = json.load(open('./ip-ranges-cloud-providers/alibaba.json', 'r'))

def check_ip_alibaba(ip):
    for range in alibaba_ranges:
        if IPAddress(ip) in IPNetwork(range):
            return True
    return False

def set_provider(ip, ip_info):
    try:
        IPAddress(ip)
        if check_ip_aws(ip):
            ip_info['provider'] = 'aws'
        elif check_ip_google(google_ranges, ip) or check_ip_google(google_cloud_ranges, ip):
            ip_info['provider'] = 'google'
        elif check_ip_azure(ip):
            ip_info['provider'] = 'azure'
        elif check_ip_cloudflare(ip):
            ip_info['provider'] = 'cloudflare'
        elif check_ip_alibaba(ip):
            ip_info['provider'] = 'alibaba'
        else:
            ip_info['provider'] = 'unknown'
    except:
        ip_info['provider'] = 'unknown'

# CAN BE mqtt, coap OR xmpp
protocol = sys.argv[1]
print('Analyzing', protocol)

shodan_endpoints = json.load(open('../shodan-crawl/scanning-results/' + protocol + '_shodan.json', 'r'))

print('File loaded, let the analysis begin!')

result = []

for endpoint in shodan_endpoints:

    endpoint_info = {}

    endpoint_info['ip'] = endpoint['ip']

    if len(endpoint['hostname']) > 0:
        endpoint_info['endpoint'] = endpoint['hostname'][0]
    else: 
        endpoint_info['endpoint'] = endpoint['ip']

    endpoint_info['countries'] = endpoint['country']

    set_provider(endpoint['ip'], endpoint_info)

    result.append(endpoint_info)

    
with open('parsed-shodan-results/general_analysis_' + protocol + '.json', 'w') as outfile:
    json.dump(result, outfile)