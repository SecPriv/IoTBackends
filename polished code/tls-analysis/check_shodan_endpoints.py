import json
import subprocess
import sys
from threading import Timer
import logging
logging.root.setLevel(logging.DEBUG)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

#python3 check_shodan_endpoints.py 0 -1 datasets/mqtt_subset_100k.json tls-results/mqtt/

testssl_path = './testssl.sh'
already_checked_endpoints = set()
timeout_sec = 120

if len(sys.argv) < 5:
    print("Missing arguments")
    exit()

batch_start = int(sys.argv[1])
batch_end = int(sys.argv[2])

endpoints_json = json.load(open(sys.argv[3]))
directory_name = sys.argv[4]
max_entries = len(endpoints_json)

if batch_end > max_entries or batch_end == -1:
    batch_end = max_entries

for i in range(batch_start, batch_end):
    endpoint = endpoints_json[i]['ip']
    if endpoint not in already_checked_endpoints:
        logging.info('Analyzing ' + endpoint)
        testssl_output = open(directory_name + '/' + endpoint + ".txt", "w")
        p = subprocess.Popen([testssl_path, '--warnings', 'batch', endpoint], stdout=testssl_output)
        timer = Timer(timeout_sec, p.kill)
        try:
            timer.start()
            p.communicate()
        finally:
            if not timer.is_alive():
                logging.info('Process was killed')
            timer.cancel()
            already_checked_endpoints.add(endpoint)
            testssl_output.close()
    else:
        logging.info(endpoint + ' was already analyzed')
already_checked_endpoints.clear()
