from shodan import Shodan
import json, time

api = Shodan('KEY')

mqtt_number = api.search('mqtt')['total']

print('Results found: {}'.format(mqtt_number))

mqtt_data = []

page_number = int(mqtt_number / 100) + 1

page_counter = 1

while page_counter <= page_number:
        try:
                mqtt_endpoints = api.search('mqtt', page=page_counter)

                print('Page number: {}'.format(page_counter))

                for result in mqtt_endpoints['matches']:

                        mqtt_single = {}

                        mqtt_single['ip'] = result['ip_str']
                        mqtt_single['hostname'] = result['hostnames']

                        mqtt_single['port'] = result['port']
                        mqtt_single['os'] = result['os']

                        try:
                                mqtt_single['connection_code'] = result['mqtt']['code']
                        except:
                                mqtt_single['connection_code'] = None

                        mqtt_single['country'] = result['location']['country_code']

                        mqtt_single['topics'] =  []

                        try:
                                for topic in result['mqtt']['messages']:
                                        mqtt_single['topics'].append(topic['topic'])
                        except:
                                pass


                        try:
                                mqtt_single['organization'] = result['org']
                        except:
                                pass

                        mqtt_data.append(mqtt_single)

                page_counter += 1
                time.sleep(8)
        except:
                time.sleep(5)

print(len(mqtt_data))

with open('../scanning_results/mqtt_shodan.json', 'w') as outfile:
    json.dump(mqtt_data, outfile)