import subprocess, sys, time, os, json

shodan_data = json.load(open('../../shodan-crawl/scanning-results/xmpp_shodan.json'))

start = int(sys.argv[1])
try:
    end = int(sys.argv[2])
except:
    end = None

scanned_ips = set()

for xmpp_endpoint in shodan_data[start:end]:

    ip = xmpp_endpoint['ip']
    port = xmpp_endpoint['port']

    if ip not in scanned_ips:
        print('creating directory for ', ip)
        os.system('mkdir security-results/' + ip)

        command_tshark = 'tshark -i ens160 -f "host ' + ip + '" -a duration:60 -w security-results/' + ip + '/traffic.pcap' 

        tshark = subprocess.Popen([command_tshark], stdout=subprocess.DEVNULL, shell=True)

        command_xmpp_info = 'nmap --script=xmpp-info ' + ip + ' -p ' + str(port)
        command_xmpp_info_2 = 'nmap --script=xmpp-info ' + ip + ' -p 5222'

        command_compliance = 'java -jar caas-app.jar user@' + ip

        command_xmpp = command_xmpp_info + ';printf "\n\n\n";' + command_xmpp_info_2 + ';printf "\n\n\n";' + command_compliance

        proc = subprocess.Popen([command_xmpp], stdout=subprocess.PIPE, shell=True)

        try:
            output, error = proc.communicate(timeout=60)
            try:
                with open('security-results/' + ip + '/xmpp.txt', 'w') as outfile:
                    outfile.write(output.decode())
            except:
                pass

        except subprocess.TimeoutExpired:
            print('Timeout expired!!')
            proc.kill()
            output, error = proc.communicate()
            try:
                with open('security-results/' + ip + '/xmpp.txt', 'w') as outfile:
                    outfile.write(output.decode())
            except:
                pass
        
        time.sleep(.5)
    
    scanned_ips.add(ip)