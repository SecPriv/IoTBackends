import json
import statistics
import sys
import logging
logging.root.setLevel(logging.DEBUG)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

protocol = sys.argv[1]

result_json_file_name = "shodan_" + protocol + ".json"
revoked_certs_file_name = "revoked_certs_" + protocol + ".json"

supported_tls = {"SSLv2" : 0, "SSLv3" : 0, "1" : 0, "1.1" : 0, "1.2" : 0, "1.3" : 0}
vulnerabilities = {"Heartbleed" : 0, "CCS" : 0, "Ticketbleed" : 0, "ROBOT" : 0, "Secure Renegotiation" : 0, "Secure Client-Initiated Renegotiation" : 0, "CRIME": 0, "POODLE" : 0, "TLS_FALLBACK_SCSV" : 0, "SWEET32" : 0, "FREAK" : 0, "DROWN" : 0, "LOGJAM" : 0, "BEAST" : 0, "LUCKY13" : 0, "Winshock" : 0, "RC4 (CVE-2013-2566, CVE-2015-2808)": 0}
certs_stats = {"cn_match_not_ok" : 0, "expired_certs" : 0, "revoked_certs" : 0, "expiration_average" : 0, "expiration_stdev" : 0, "endpoint_with_revocation_list" : 0}
certs_expiration_days = []
tls_enabled_counter = 0
no_tls_enabled_counter = 0
not_reachable_counter = 0
analysis_not_finished_counter = 0
num_of_endpoints_with_revocation_list = 0

def evaluate_supoprted_TLS_version (endpoint):
    global tls_enabled_counter
    supported_tls_json = endpoint["supported_tls"]
    if supported_tls_json:
        tls_enabled_counter += 1
    for tls_version in supported_tls_json:
        supported_tls[tls_version.strip()] += 1

def evaluate_vulnerabilities (endpoint):
    vulnerabilities_json = endpoint["vulnerabilities"]
    for vulnerability in vulnerabilities_json:
        vulnerabilities[vulnerability.strip()] += 1

def evaluate_cn_match (cert):
    cn_match = cert["cn_match"]
    if cn_match == "NOK":
        certs_stats["cn_match_not_ok"] += 1

def evaluate_expiration (cert, path):
    expiration_days = cert["expiration_date_in_days"]
    if expiration_days == -1:
        logging.info("Expired cert in " + path)
        certs_stats["expired_certs"] += 1
    else:
        certs_expiration_days.append(expiration_days)

def evaluate_revocation (cert, path):
    revocation_list = cert["revocation_list"]
    has_revocation_list = False
    if revocation_list:
        has_revocation_list = True
        revoked_certs_json = json.load(open(path + revoked_certs_file_name))
        if revoked_certs_json:
            certs_stats["revoked_certs"] += len(revoked_certs_json)
    return has_revocation_list

def evaluate_certs (endpoint, path):
    global num_of_endpoints_with_revocation_list
    certs_json = endpoint["certs"]
    has_revocation_list = False
    for cert in certs_json:
        evaluate_cn_match(cert)
        evaluate_expiration(cert, path)
        if evaluate_revocation(cert, path):
            has_revocation_list = True
    if has_revocation_list:
        num_of_endpoints_with_revocation_list += 1


def evaluate_result_json (path):
    global no_tls_enabled_counter, analysis_not_finished_counter, not_reachable_counter
    result_json = json.load(open(path + result_json_file_name))

    for endpoint_json in result_json:
        endpoint_result = result_json[endpoint_json]
        status = endpoint_result["analysis_state"]
        if status == "Done":
            evaluate_supoprted_TLS_version(endpoint_result)
            evaluate_vulnerabilities(endpoint_result)
            evaluate_certs(endpoint_result, path)
        elif status == "TLS not enabled":
            no_tls_enabled_counter += 1
        elif status == "Analysis not finished":
            logging.info("Endpoint did not finish: " + endpoint_json + " in " + path)
            analysis_not_finished_counter += 1
        else:
            not_reachable_counter += 1

summary_json = {}

evaluate_result_json('tls-results/')

if certs_expiration_days and len(certs_expiration_days) > 1:
    certs_stats["expiration_average"] = statistics.mean(certs_expiration_days)
    certs_stats["expiration_stdev"] = statistics.stdev(certs_expiration_days)
certs_stats["endpoint_with_revocation_list"] = num_of_endpoints_with_revocation_list
summary_json["tls_enabled"] = tls_enabled_counter
summary_json["supported_tls_version"] = supported_tls
summary_json["vulnerabilities"] = vulnerabilities
summary_json["certs"] = certs_stats
summary_json["no_tls_enabled"] = no_tls_enabled_counter
summary_json["not_reachable"] = not_reachable_counter
summary_json["analysis_not_finished"] = analysis_not_finished_counter

json.dump(summary_json, open(protocol + "_summary.json", "w+"))
