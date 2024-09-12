import json
import os
import re
import sys
from datetime import datetime

tested_vulnerabilities = ["Heartbleed", "CCS", "Ticketbleed", "ROBOT", "Secure Renegotiation", "Secure Client-Initiated Renegotiation", "CRIME", "POODLE", "TLS_FALLBACK_SCSV", "SWEET32", "FREAK", "DROWN", "LOGJAM", "BEAST", "LUCKY13", "Winshock", "RC4 (CVE-2013-2566, CVE-2015-2808)"]


#### Regex patterns ####
ssl_version_regex = r"(SSLv\d)(.*)"
tls_version_regex = r"(TLS\s(\d.?\d?))\s*(.*)"
serial_regex = r"Serial\s*([\w\d]*)\s"
common_regex = r"Common Name (CN)\s*([\w\d]*)\s"
date_regex = r"\s(\d\d\d\d-\d\d-\d\d\s\d\d:\d\d)"
start_date_regex = r"Start\s(\d\d\d\d-\d\d-\d\d\s\d\d:\d\d)"
ansi_regex = r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
done_regex = r'Done\s\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d'
########################

def get_subsection (contents, start_text, end_text):
    start_index = contents.find(start_text)
    end_index = contents.find(end_text)
    return contents[start_index:end_index]

def get_multiple_subsections (contents, start_text, end_text):
    findings = []
    i = 0
    j = 0
    start_index = 0
    while start_index != -1:
        start_index = contents.find(start_text, i)
        end_index = contents.find(end_text, j)
        if start_index != -1:
            content = remove_ansi(contents[start_index:end_index])
            findings.append(content)
        i = start_index + 1
        j = end_index + 1
    return findings

def get_tlsversion (contents):
    supported_tls_versions = []
    ssl_version_text = get_subsection(contents, "Testing protocols", "Testing cipher categories")
    pattern = re.compile(ssl_version_regex)
    for match in pattern.finditer(ssl_version_text):
        not_offered = match.group(2).find("not offered")
        if not_offered == -1:
            supported_tls_versions.append(match.group(1))
    pattern = re.compile(tls_version_regex)
    for match in pattern.finditer(ssl_version_text):
        not_offered = match.group(3).find("not offered")
        if not_offered == -1:
            supported_tls_versions.append(match.group(2))

    return supported_tls_versions

def remove_ansi (text):
    ansi_escape = re.compile(ansi_regex)
    return ansi_escape.sub('', text)

def get_serial (contents):
    serial_text = remove_ansi(contents)
    serial_result = re.search(serial_regex, serial_text)
    return serial_result.group(1)

def get_revocation_list (list):
    revocation_list_text = remove_ansi(list)
    revocation_list_text = revocation_list_text.replace("Certificate Revocation List", "").strip()
    revocation_list = revocation_list_text.split("\n")
    revocation_list = [entry.strip() for entry in revocation_list if entry.find("--") == -1]
    return revocation_list


def get_cn_match (cn_match):
    if cn_match.lower().find("not ok") == -1 and cn_match.lower().find("certificate does not match supplied uri") == -1:
        return 'OK'
    return "NOK"

def get_certificate_validity (certificate_validity):
    expiration_result = re.search(date_regex, certificate_validity)
    start_date_result = re.search(start_date_regex, contents)
    date_format = "%Y-%m-%d %H:%M"
    expiration_date = datetime.strptime(expiration_result.group(1), date_format)
    start_date = datetime.strptime(start_date_result.group(1), date_format)
    delta = expiration_date - start_date
    if delta.days < 0:
        return -1
    return delta.days

def get_common_name (contents):
    common_text = remove_ansi(contents)
    print(common_text)
    common_result = common_text.replace('Common Name (CN)','').strip(' ').strip('\n')
    return common_result

def get_server_certificate_information (contents):
    certs = []
    certificates_validity = get_multiple_subsections(contents, "Certificate Validity (UTC)", "ETS")
    serials = get_multiple_subsections(contents, "Serial", "Fingerprints")
    revocation_lists = get_multiple_subsections(contents, "Certificate Revocation List", "OCSP URI")
    cn_matches = get_multiple_subsections(contents, "Trust (hostname)", "Chain of trust")
    common_name = get_multiple_subsections(contents, 'Common Name (CN)', 'subjectAltName')
    for i in range(len(certificates_validity)):
        cert = {}
        cert["serial"] = get_serial(serials[i])
        cert["revocation_list"] = get_revocation_list(revocation_lists[i])
        cert["cn_match"] = get_cn_match(cn_matches[i])
        cert["expiration_date_in_days"] = get_certificate_validity(certificates_validity[i])
        cert['common_name'] = get_common_name(common_name[i])
        certs.append(cert)
    return certs

def get_vulnerabilities (contents):
    found_vulnerabilities = []
    contents_ansi_removed = remove_ansi(contents)
    for i in range(len(tested_vulnerabilities)):
        tested_vulnerability = tested_vulnerabilities[i]
        if i < len(tested_vulnerabilities) - 1:
            vulnerability = get_subsection(contents_ansi_removed, tested_vulnerability, tested_vulnerabilities[i+1])
        else:
            vulnerability = get_subsection(contents_ansi_removed, tested_vulnerability, "Running client simulations")
        if (vulnerability.find("VULNERABLE") != -1 or vulnerability.find("NOT ok") != -1) and vulnerability.find("potentially") == -1:
            found_vulnerabilities.append(tested_vulnerabilities[i])
    return found_vulnerabilities



def get_analysis_status (contents):
    done_text = re.search(done_regex, contents)
    start_text = re.search(start_date_regex, contents)
    if contents.find("doesn't seem to be a TLS/SSL enabled server") != -1:
        return "TLS not enabled"
    if contents.find("TCP connect problem") != -1 or not start_text:
        return "Not available"
    if done_text:
        return "Done"
    if start_text and contents.find("Testing protocols") != -1:
        return "Analysis not finished"
    return "Not available"

def get_first_ip_result (contents):
    start_text = re.search(start_date_regex, contents)
    done_text = re.search(done_regex, contents)
    start_index = contents.find(start_text.group())
    done_index = contents.find(done_text.group())
    return contents[start_index:done_index]


base_folder = 'tls-results/'

endpoint_type = sys.argv[1] 
protocol = sys.argv[2]

result = {}
certificates_common_names = {}

if protocol == 'mqtt':
    whole_path = base_folder + 'mqtt/'
elif protocol == 'xmpp':
    whole_path = base_folder + 'xmpp/'

for file in os.listdir(whole_path):
    output_json = {}
    if file.endswith(".json"):
        continue
    with open(whole_path + file, "r", encoding="latin-1") as testssl_output:
        contents = testssl_output.read()
        status = get_analysis_status(contents)
        output_json["analysis_state"] = status
        if status == "Done":
            first_ip_result = get_first_ip_result(contents)
            output_json["certs"] = get_server_certificate_information(first_ip_result)

        endpoint_name = file.replace(".txt", "")

        certificates_common_names[endpoint_name] = {"common_names": [], 'cn_match': []}
        if 'certs' in output_json:
            for c in output_json['certs']:
                certificates_common_names[endpoint_name]['common_names'].append(c['common_name'])
                certificates_common_names[endpoint_name]['cn_match'].append(c['cn_match'])
        
        result[endpoint_name] = output_json

json.dump(certificates_common_names, open(base_folder + protocol +  "_commonname.json", "w+"))
