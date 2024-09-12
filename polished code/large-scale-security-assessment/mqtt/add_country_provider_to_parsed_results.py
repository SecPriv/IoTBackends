import json

mqtt_results = {}

parsed_results = json.load(open('mqtt_parsed_2022.json', 'r'))
general_analysis = json.load(open('../../dataset-analysis/parsed-shodan-results/general_analysis_mqtt'))

for endpoint, value in parsed_results.items():
    mqtt_results[endpoint] = value
    if endpoint in general_analysis:
        mqtt_results[endpoint]['provider'] = general_analysis[endpoint]['provider']
        mqtt_results[endpoint]['country'] = general_analysis[endpoint]['countries']

with open('mqtt_total_2022.json', 'w') as output_file:
    json.dump(mqtt_results, output_file)