import json

total_mqtt = json.load(open('mqtt_total_2022.json', 'r'))

providers_clients =  {}

europe_country_codes = [
    "AL", "AD", "AM", "AT", "BY", "BE", "BA", "BG", "HR", "CY", 
    "CZ", "DK", "EE", "FI", "FR", "GE", "DE", "GR", "HU", "IS", 
    "IE", "IT", "KZ", "LV", "LI", "LT", "LU", "MK", "MT", "MD", 
    "MC", "ME", "NL", "NO", "PL", "PT", "RO", "SM", "RS", 
    "SK", "SI", "ES", "SE", "CH", "TR", "UA", "GB", "VA"
]

asia_country_codes = [
    "AF", "AM", "AZ", "BH", "BD", "BT", "BN", "KH", "CN", "CY", 
    "GE", "IN", "ID", "IR", "IQ", "IL", "JP", "JO", "KZ", "KW", 
    "KG", "LA", "LB", "MY", "MV", "MN", "MM", "NP", "KP", "OM", 
    "PK", "PS", "PH", "QA", "SA", "SG", "KR", "LK", "SY", "TW", 
    "TJ", "TH", "TL", "TR", "TM", "AE", "UZ", "VN", "YE"
]

south_america_country_codes = [
    "AR", "BO", "BR", "CL", "CO", "EC", "GY", "PE", "PY", "SR", "UY", "VE"
]

north_america_country_codes = [
    "CA", "US", "MX"
]

africa_country_codes = [
    "DZ", "AO", "BJ", "BW", "BF", "BI", "CM", "CV", "CF", "TD", "KM", 
    "CG", "CD", "DJ", "EG", "GQ", "ER", "SZ", "ET", "GA", "GM", "GH", 
    "GN", "GW", "CI", "KE", "LS", "LR", "LY", "MG", "MW", "ML", "MR", 
    "MU", "MA", "MZ", "NA", "NE", "NG", "RW", "ST", "SN", "SC", "SL", 
    "SO", "ZA", "SS", "SD", "TZ", "TG", "TN", "UG", "ZM", "ZW", "EH"
]

oceania_country_codes = [
    "AS", "AU", "CK", "FJ", "PF", "KI", "MH", "FM", "NR", "NC", "NZ", 
    "NU", "NF", "MP", "PW", "PG", "PN", "WS", "SB", "TK", "TO", "TV", "VU", "WF"
]

capitalized_providers = {"aws": "AWS", 'google': 'Google', 'unknown': 'Unknown', 'azure': 'Azure', 'alibaba': 'Alibaba', 'cloudflare': 'Cloudflare'}

country_clients = {}

def country_categorization(e):
    if 'country' in e:
        if e['country'] in europe_country_codes:
            return 'Europe'
        elif e['country'] in asia_country_codes:
            return 'Asia'
        elif e['country'] in north_america_country_codes:
            return 'North America'
        elif e['country'] in south_america_country_codes:
            return 'South America'
        elif e['country'] in africa_country_codes:
            return 'Africa'
        elif e['country'] in oceania_country_codes:
            return 'Oceania'
        elif e['country'] == 'RU':
            return 'Russia'
    return 'Other'
        
countries = {}

for backend, value in total_mqtt.items():
    
    provider = value['provider']
    continent = country_categorization(value)

    if continent not in countries:
        countries[continent] = 1
    else:
        countries[continent] += 1


    if capitalized_providers[provider] not in providers_clients:
        providers_clients[capitalized_providers[provider]] = []

    if 'connected_hosts' in value and value['connected_hosts'] != '':
        try:
            if int(value['connected_hosts']) > 0:
                
                providers_clients[capitalized_providers[provider]].append(int(value['connected_hosts']))
        except:
            pass

    
    if continent not in country_clients:
        country_clients[continent] = []

    if 'connected_hosts' in value and value['connected_hosts'] != '':
        try:
            if int(value['connected_hosts']) > 0:
                country_clients[continent].append(int(value['connected_hosts']))
        except:
            pass

import matplotlib.pyplot as plt

fig, ax=plt.subplots()

# Create a boxplot, CHANGE TO country_clients FOR THE COUNTRY BOXPLOT
plt.boxplot(providers_clients.values(), labels=providers_clients.keys())
plt.xticks(fontsize=12) 

ax.set_yscale("log")

fig.autofmt_xdate()

# plt.title('MQTT Connected Clients per Provider', fontsize=20)
# plt.xlabel('Continents', fontsize=16)
# plt.ylabel('Connected Clients (log scale)', fontsize=16)

plt.yticks([1, 10, 100, 1000, 10000], ['1', '10', '100', '1k', '10k'])
plt.show()
# plt.savefig('mqtt_connected_clients_providers.pdf')
