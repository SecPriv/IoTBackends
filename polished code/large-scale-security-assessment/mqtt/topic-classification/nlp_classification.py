#!pip install transformers[sentencepiece]
from transformers import pipeline
import json, sys

# Totally, there are 1717765 regular topics
# And 50167 SYS topics

hypothesis_template = "This example is about {}"

start = int(sys.argv[1])
end = int(sys.argv[2])

file_number = sys.argv[3]

REGULAR_TOPICS = json.load(open('mqtt_regular_topics.json', 'r'))

classes_verbalized = ["health", "home", "security", "update", "sensor", "location", "industry", "transportation", "identifier"]
zeroshot_classifier = pipeline("zero-shot-classification", model="MoritzLaurer/deberta-v3-large-zeroshot-v1.1-all-33", device=0, batch_size=32)

output = zeroshot_classifier(REGULAR_TOPICS[start:end], classes_verbalized, hypothesis_template=hypothesis_template, multi_label=False)

json.dump(output, open('classified/mqtt_topics_classified' + file_number + '.json', 'w+'))