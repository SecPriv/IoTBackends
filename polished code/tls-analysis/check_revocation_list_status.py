import subprocess
import json
import urllib.request
import sys
import logging
logging.root.setLevel(logging.DEBUG)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

output_path = sys.argv[1]
protocol = sys.argv[2]

def check_certificate_revocation ():
    revoked_certs_endpoints = {}
    result_json = json.load(open(output_path + "shodan_" + protocol + ".json"))
    for endpoint in result_json:
        logging.info('Analyzing ' + endpoint)
        endpoint_result = result_json[endpoint]
        revoked_certs = []
        if "certs" in endpoint_result:
            certs = endpoint_result['certs']
            for cert in certs:
                serial = cert["serial"]
                revocation_lists = cert["revocation_list"]
                if revocation_lists:
                    for url in revocation_lists:
                        revoked = check_if_serial_contained_in_file(serial, url)
                        if revoked:
                            revoked_certs.append({"serial": serial, "revocation_list": url})
        if revoked_certs:
            revoked_certs_endpoints[endpoint] = revoked_certs
    return revoked_certs_endpoints


def get_revocation_list_file (url):
    with urllib.request.urlopen(url) as f:
        return f.read()

def check_if_serial_contained_in_file (serial, url):
    logging.info('Checking serial: ' + serial + " in url: " + url)
    file_content = get_revocation_list_file(url)
    logging.info('Fetched file content')
    p = subprocess.Popen(['openssl', 'crl', '-text', '-noout'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    logging.info('OpenSSL conversion done')
    stdout = p.communicate(input=file_content)[0]
    output = stdout.decode()
    serial_found_index = output.find(serial)
    return serial_found_index != -1


revoked_certificates = check_certificate_revocation()
json.dump(revoked_certificates, open(output_path + "revoked_certs_" + protocol + ".json", "w+"))
