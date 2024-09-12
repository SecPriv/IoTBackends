import json
from packaging import version

versions = json.load(open('summarized_results_2022.json', 'r'))['versions']

total = 0

for v in versions.values():
    total += v

print('We identified the version for', total, 'backends')

manually_parsed_versions = json.load(open('versions_2022.json', 'r'))

count = 0
vulnerable_version = '1.5'

for k,v in manually_parsed_versions.items():
    if version.parse(k) < version.parse(vulnerable_version):
        count += v

print('We identified', count, 'backends with a version lower than', vulnerable_version)