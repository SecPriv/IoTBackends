import json

# Totally, there are 1717765 regular topics
# And 50167 SYS topics

TOTAL_MQTT = json.load(open('../mqtt_total_2022.json', 'r'))

SYS_TOPICS = set()
REGULAR_TOPICS = set()

def categorize_topic(t):
    if '$SYS/' in t:
        SYS_TOPICS.add(t)
    else:
        REGULAR_TOPICS.add(t)

for backend, values in TOTAL_MQTT.items():
    if 'unique_topics' in values and len(values['unique_topics']) > 0:
        for topic in values['unique_topics']:
            categorize_topic(topic)

print('Totally, there are', len(REGULAR_TOPICS), 'regular topics')
print('And', len(SYS_TOPICS), 'SYS topics')

json.dump(list(REGULAR_TOPICS), open('mqtt_regular_topics.json', 'w+'))
json.dump(list(SYS_TOPICS), open('mqtt_sys_topics.json', 'w+'))