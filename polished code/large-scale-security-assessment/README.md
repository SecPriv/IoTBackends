# Directory Structure and File Order of Execution

The following folder contains all the scripts for the security assessment of backends and the evaluation of the results.

## MQTT

`mqtt/` contains the scripts for evaluating MQTT backends. 

1. `mqtt_security_assessment.py` takes as input the start and end of the batch of Shodan MQTT backends (passed as a JSON file) to analyze and then tries to connect and record all topics for 40 seconds. Further, it tests via cotopaxi for known DoS vulnerabilities. The script is completed by `mqtt_connect.py`, which is automatically executed. A folder for each backend is created containing a JSON file and the pcap file of the exchanged traffic.
2. `parse_results.py` iterates over all the backends' directories and parses the results, looking for information leaks and DoS vulnerabilities. It outputs a JSON file with all parsed results. For a more compact version of the results (e.g., only showing how many topics on average are collected and how many backends are affected by DoS vulnerabilities), run `summarize_results.py` on the output of the previous script.
3. `add_country_provider_to_parsed_results.py` is necessary to add the country and provider to the output of `parse_results.py`. The output file is then used to run `connected_clients_boxplot.py`, plotting how many connected clients per backend can be grouped by geographical region or provider (see Appendix D in the paper).
4. `get_vulnerable_mqtt.py` returns a file with only the vulnerable MQTT backends. It organizes the vulnerabilities by vulnerability classes, either **information_leakage** or **DoS**. It takes the resulting file of script (3) as input.
5. `software_versions_analysis.py` analyses the versions collected for MQTT backends and checks which ones have a version lower than a specified one (meaning they are potentially vulnerable CVEs affecting older software versions).
6. Finally, `topic-classification` runs a zero-shot classification model to cluster MQTT topics. First, `get_regular_or_sys_topics.py` distinguishes SYS or regular topics as we are only interested in categorizing the latter. `nlp_classification.py` performs the actual classification. We ran the script on a machine with 128GB of RAM and an NVIDIA A100 GPU with 40GB of RAM. `topic_distribution.py` prints the distribution, and `plot_topic_distribution.py` plots the distribution into a histogram.

## CoAP

`coap/` contains the scripts for evaluating CoAP backends.
1. `coap_security_assessment.py` takes as input the start and end of the batch of Shodan CoAP backends (passed as a JSON file) to analyze and then tries to connect, fingerprint the backend, and perform a HEAD request to all the resources listed in `coap_resources.txt`. Further, it tests via cotopaxi for known DoS and amplification vulnerabilities. A folder for each backend is created containing a txt file and the pcap file of the exchanged traffic.
2. `parse_results.py` iterates over all the backends' directories and parses the results, looking for information leaks and DoS vulnerabilities. It outputs a JSON file with all parsed results. 
3. `extract_active_endpoints.py` extracts all the return codes of the HEAD requests. The output is saved into a JSON file. `count_available_resources.py` counts how many resources are available, hence returning a code 2.05.
4. `coap_connection_and_ampl_parser.py` is necessary to add the country, provider, amplification factor, and connection status to the output of `parse_results.py`. For a more compact version of the results (e.g., only showing how many topics on average are collected and how many backends are affected by DoS vulnerabilities), run `summarize_results.py` on the output of the previous script.
5. `get_vulnerable_coap.py` returns a file with only the vulnerable CoAP backends. It organizes the vulnerabilities by vulnerability classes, either **information_leakage**, **DoS**, or **amplification_vulnerability**. Takes as input the resulting file of scripts (2) and (4).

## XMPP

`xmpp/` contains the scripts for evaluating XMPP backends.
1. `xmpp_security_assessment.py` takes as input the start and end of the batch of Shodan XMPP backends (passed as a JSON file) to analyze and then tries to connect, fingerprint the backend, and register a dummy *user*. A folder for each backend is created containing a txt file and the pcap file of the exchanged traffic.
2. `parse_results.py` iterates over all the backends' directories and parses the results, looking for information leaks and weak authentication vulnerabilities. It outputs a JSON file with all parsed results. 
3. For a more compact version of the results (e.g., only showing how many topics on average are collected and how many backends are affected by DoS vulnerabilities), run `summarize_results.py` on the output of the previous script.
4. `successful_connections.py` gets the number of connections that were successful, or failed because of port close/filtered errors.
5. `get_vulnerable_xmpp.py` returns a file with only the vulnerable CoAP backends. It organizes the vulnerabilities by vulnerability classes, either **information_leakage** or **weak_authentication**. Takes as input the resulting file of script (2).

## Summarizing Scripts

The main folder contains the scripts we used to evaluate the results of our 2022, 2023, and 2024 run. Those results can be found in the paper in Sections 6.7 and 7. Specifically:
1. `count_dos_coap.py` counts how many CoAP backends in 2022 are affected by DoS and amplification vulnerabilities and checks their geographical and provider distribution. 
2. `count_dos_mqtt.py` counts how many MQTT backends in 2022 and 2023 are affected by DoS vulnerabilities and checks their geographical and provider distribution. 
3. `count_info_leak_mqtt.py` counts how many MQTT backends in 2022 and 2023 leak some information and checks their geographical and provider distribution. Further, it counts how many MQTT topics are leaked by country in 2022.
4. `count_offline.py` counts how many vulnerable backends became offline in 2022, 2023, and 2024. The script takes the protocol (i.e., mqtt, coap, or xmpp) as input. 
5. `count_resources_coap.py` counts how many CoAP backends in 2022 and 2023 expose resources and checks their geographical and provider distribution. 
6. `parse_diff_new.py` takes the diff file computed for 2024 and checks how the vulnerable endpoints evolved over time (e.g., how many became offline, fixed the issues, or new ones became vulnerable) for all three protocols. The output JSON file is then taken as input by `trend_plot.py`, which displays the evolution in the form of a histogram for CoAP and MQTT backends (we did not have enough XMPP backends to show any trend).
7. `get_diff_coap.py`, `get_diff_mqtt.py`, and `get_diff_xmpp.py` take the vulnerable backends file for each year (and in case of 2024 also the diff between 2022 and 2023) and check for how many backends the situation has changed or how many became offline. The output is a new diff file containing the results of previous year(s) plus the updated status. `status_<date>` checks whether the backend is still online at given date. If online, `update_<date>` contains the new security assessment results for the current date; If missing, the situation stayed the same, if empty, the backend is no longer vulnerable.
   
## Note

Most scripts' results and 2023/2024 data are not available in the repository for confidentiality reasons (we cannot risk vulnerable backends to be exploited). In case you need access, please contact us by email.