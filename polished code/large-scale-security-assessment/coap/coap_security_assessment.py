import subprocess, sys, time, os, json

start = int(sys.argv[1])
try:
    end = int(sys.argv[2])
except:
    end = None

scanned_ips = set()

shodan_data = json.load(open('../../shodan-crawl/scanning-results/coap_shodan.json'))[start:end]

for coap_endpoint in shodan_data:

    ip = coap_endpoint['ip']
    port = coap_endpoint['port']

    if ip not in scanned_ips:
        print('creating directory for ', ip)
        os.system('mkdir security-results/' + ip)

        command_tshark = 'tshark -i ens160 -f "host ' + ip + '" -a duration:60 -w security-results/' + ip + '/traffic.pcap' 

        tshark = subprocess.Popen([command_tshark], stdout=subprocess.DEVNULL, shell=True)

        command_cotopaxi_fingerprint = 'python3 -m cotopaxi.server_fingerprinter ' + ip + ' ' + str(port) + ' --protocol CoAP'
        command_cotopaxi_resources = 'python3 -m cotopaxi.resource_listing ' + ip + ' ' + str(port) + ' coap/coap_resources.txt --protocol CoAP'
        command_cotopaxi_vulnerability = 'python3 -m cotopaxi.vulnerability_tester ' + ip + ' ' + str(port) + ' --protocol CoAP'

        command_cotopaxi = command_cotopaxi_fingerprint + ';printf "\n\n\n";' + command_cotopaxi_resources + ';printf "\n\n\n";' + command_cotopaxi_vulnerability

        proc = subprocess.Popen([command_cotopaxi], stdout=subprocess.PIPE, shell=True)

        try:
            output, error = proc.communicate(timeout=60)
            try:
                with open('security-results/' + ip + '/cotopaxi.txt', 'w') as outfile:
                    outfile.write(output.decode())
            except:
                pass
        except subprocess.TimeoutExpired:
            print('Timeout expired!!')
            proc.kill()
            output, error = proc.communicate()
            try:
                with open('security-results/' + ip + '/cotopaxi.txt', 'w') as outfile:
                    outfile.write(output.decode())
            except:
                pass
        
        time.sleep(5)
    
    scanned_ips.add(ip)