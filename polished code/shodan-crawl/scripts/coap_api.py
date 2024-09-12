from shodan import Shodan
import json, time

api = Shodan('KEY')

coap_number = api.search('coap')['total']

print('Results found: {}'.format(coap_number))

coap_data = []

page_number = int(coap_number / 100) + 1

page_counter = 1

while page_counter <= page_number:
        try:
                coap_endpoints = api.search('coap', page=page_counter)

                print('Page number: {}'.format(page_counter))

                for result in coap_endpoints['matches']:

                        coap_single = {}

                        coap_single['ip'] = result['ip_str']
                        coap_single['hostname'] = result['hostnames']

                        coap_single['port'] = result['port']
                        coap_single['os'] = result['os']


                        coap_single['country'] = result['location']['country_code']

                        coap_single['data'] = result['data']

                        coap_single['resources'] =  []

                        try:
                                for value, attr in result['coap']['resources'].items():
                                        coap_single['resources'].append(value)
                        except:
                                pass

                        try:
                                coap_single['organization'] = result['org']
                        except:
                                pass

                        coap_data.append(coap_single)

                page_counter += 1
                time.sleep(5)
        except:
                time.sleep(5)

print(len(coap_data))

with open('../scanning_results/coap_shodan.json', 'w') as outfile:
    json.dump(coap_data, outfile)