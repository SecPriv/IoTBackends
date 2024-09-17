import json, re, csv, sys

protocol = sys.argv[1]

shodan_file = json.load(open('../../shodan-crawl/scanning-results/' + protocol + '_shodan.json'))

result_file_name = 'deep_dive_match_' + protocol + '.json'

AWS_REGEX = '.*\.iot\..*\..*amazonaws.com'

base_folder = '/home/martina/datasets/'
folders = ['shodan_endpoints/', 'traffic_endpoints/']
csv_regex_pattern = []
domain_matches = {}

def get_regex_and_name_from_censys_csv ():
    with open('top16_companies_censys_patterns.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            csv_entry = {}
            if line_count == 0:
                line_count += 1
            else:
                csv_entry['regex'] = row[0]
                csv_entry['company_name'] = row[1]
                csv_regex_pattern.append(csv_entry)

def get_regex_and_name_from_dnsdb_csv ():
    with open('top16_companies_dnsdb_patterns.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            csv_entry = {}
            if line_count == 0:
                line_count += 1
            else:
                csv_entry['regex'] = row[1][0:len(row[1]) - 2]
                csv_entry['company_name'] = row[0]
                csv_regex_pattern.append(csv_entry)


def add_domain_match (ip, entry):
    if ip in domain_matches:
        entries_for_ip = domain_matches[ip]
        entries_for_ip.append(entry)
    else:
        domain_matches[ip] = [entry]

def check_regex(domain_name, ip):
    matched_domain = re.search(AWS_REGEX, domain_name)
    if matched_domain:
        add_domain_match(ip, domain_name)
    # for entry in csv_regex_pattern:
    #     matched_domain = re.search(entry['regex'], domain_name)
    #     if matched_domain:
    #         entry = (domain_name, entry['company_name'])
    #         add_domain_match(ip, entry)

def check_shodan_domains (endpoints_json):
    count = 0
    print('Starting now, will take a while..')
    print('Total to analyze: ', len(endpoints_json))
    for endpoint in endpoints_json:
        if count % 1000 == 0:
            print('Analyzed', count, 'entries')
        endpoint_ip = endpoint['ip']
        endpoint_hostnames = endpoint['hostname']
        for hostname in endpoint_hostnames:
            check_regex(hostname, endpoint_ip)
        count += 1

get_regex_and_name_from_censys_csv()
get_regex_and_name_from_dnsdb_csv()

check_shodan_domains(shodan_file)

json.dump(domain_matches, open(result_file_name, 'w+'))