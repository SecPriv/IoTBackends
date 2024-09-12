import json, os

topic_distribution = {}

for filename in os.listdir('classified/'):
    if 'mqtt_topics_classified' in filename:
        mqtt_classified = json.load(open('classified/' + filename, 'r'))
        for topic in mqtt_classified:
            if topic['scores'][0] > 0.85:
                if topic['labels'][0] not in topic_distribution:
                    topic_distribution[topic['labels'][0]] = 1
                else:
                    topic_distribution[topic['labels'][0]] += 1
            else:
                if 'other' not in topic_distribution:
                    topic_distribution['other'] = 1
                else:
                    topic_distribution['other'] += 1

print(topic_distribution)