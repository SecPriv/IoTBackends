from shodan import Shodan
import json, time

api = Shodan('KEY')

xmpp_number = api.search('xmpp')['total']

print('Results found: {}'.format(xmpp_number))

xmpp_data = []

page_number = int(xmpp_number / 100) + 1

page_counter = 1

while page_counter <= page_number:
        try:
                xmpp_endpoints = api.search('xmpp', page=page_counter)

                print('Page number: {}'.format(page_counter))

                for result in xmpp_endpoints['matches']:

                        xmpp_single = {}

                        xmpp_single['ip'] = result['ip_str']
                        xmpp_single['hostname'] = result['hostnames']

                        xmpp_single['port'] = result['port']
                        xmpp_single['os'] = result['os']


                        xmpp_single['country'] = result['location']['country_code']

                        xmpp_single['data'] =  result['data']

                        xmpp_data.append(xmpp_single)

                page_counter += 1
                time.sleep(8)
        except:
                time.sleep(5)

print(len(xmpp_data))

with open('../scanning_results/xmpp_shodan.json', 'w') as outfile:
    json.dump(xmpp_data, outfile)