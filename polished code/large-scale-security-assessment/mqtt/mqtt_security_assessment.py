import json, sys, subprocess, time, os
import mqtt_connect


start = int(sys.argv[1])
try:
    end = int(sys.argv[2])
except:
    end = None

scanned_ips = set()

shodan_data = json.load(open('../../shodan-crawl/scanning-results/mqtt_shodan.json'))[start:end]

for mqtt_endpoint in shodan_data:

    rc = mqtt_endpoint['connection_code']
    ip = mqtt_endpoint['ip']
    port = mqtt_endpoint['port']

    scan_result = {}


    if ip not in scanned_ips and not os.path.isdir('security-results/' + ip):
        print('creating directory for ', ip)
        os.system('mkdir security-results/' + ip)

        command_tshark = 'tshark -i ens160 -f "host ' + ip + '" -a duration:60 -w security-results/' + ip + '/traffic.pcap' 
        tshark = subprocess.Popen([command_tshark], stdout=subprocess.DEVNULL, shell=True)

        # check connection code
        if rc == 0:
            # connection successful
            scan_result = mqtt_connect(ip, port, None, None, 3)
            
        elif rc == 1:
            #1: Connection refused – incorrect protocol version (try MQTTv5)
            scan_result = mqtt_connect(ip, port, None, None, 5)

        elif rc == 3:
            #3: Connection refused – server unavailable
            print('Server not available', ip)
            continue

        elif rc == 5:
            #5: Connection refused – not authorised
            pass
        else:
            continue

        if scan_result == -1:
            with open('security-results/' + ip + '/mqtt.txt', 'w') as output_file:
                output_file.write('Connection timed out')
            continue
        else:
            with open('security-results/' + ip + '/mqtt.json', 'w') as output_file:
                json.dump(scan_result, output_file)
    
        # run cotopaxi on known vulnerabilities
        command_cotopaxi = 'python3 -m cotopaxi.vulnerability_tester ' + ip + ' ' + str(port) + ' --protocol MQTT'
        command_mqtt = command_cotopaxi

        proc = subprocess.Popen([command_mqtt], stdout=subprocess.PIPE, shell=True)

        try:
            output, error = proc.communicate(timeout=60)
            try:
                with open('security-results/' + ip + '/mqtt.txt', 'w') as outfile:
                    outfile.write(output.decode())
            except:
                pass

        except subprocess.TimeoutExpired:
            print('Timeout expired!!')
            proc.kill()
            output, error = proc.communicate()
            try:
                with open('security-results/' + ip + '/mqtt.txt', 'w') as outfile:
                    outfile.write(output.decode())
            except:
                pass
        
        time.sleep(5)
    
    scanned_ips.add(ip)