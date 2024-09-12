import json, sys

# CAN BE mqtt, coap OR xmpp
protocol = sys.argv[1]
print('Analyzing', protocol)

shodan_endpoints = json.load(open('parsed-shodan-results/general_analysis_' + protocol + '.json', 'r'))

countries = {}

for endpoint in shodan_endpoints:
    try:
        try:
            countries[endpoint['countries']] += 1
        except:
            countries[endpoint['countries']] = 1
    except:
        pass

with open('country-analysis/country_' + protocol + '.json', 'w') as outfile:
    json.dump(countries, outfile)
