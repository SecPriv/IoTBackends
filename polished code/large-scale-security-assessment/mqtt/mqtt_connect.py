import paho.mqtt.client as mqtt
import time, sys

def mqtt_connect(domain, port):

    total_info = {}

    sys_info_topics = ['$SYS/broker/version', '$SYS/broker/timestamp', '$SYS/broker/uptime', '$SYS/broker/subscriptions/count', '$SYS/broker/clients/connected', '$SYS/broker/clients/expired', '$SYS/broker/clients/disconnected', '$SYS/broker/clients/maximum', '$SYS/broker/clients/total']

    system_info = {}
    message_list = []
    topic_set = []

    def do_system_info(client):
        for topic in sys_info_topics:
            client.subscribe(topic, 0)
            time.sleep(.2)

    def discovery(client):
        client.subscribe('#', 0)
        client.subscribe('$SYS/#', 0)

    def on_message(client, obj, msg):
        """Handles when a new message arrives"""
        if msg.topic in sys_info_topics:
            system_info[msg.topic.split('/')[-1]] = msg.payload.decode()
        else:
            message = {}
            message['topic'] = msg.topic
            message['payload'] = msg.payload.decode()
            message_list.append(message)

        if msg.topic not in topic_set:
            topic_set.append(msg.topic)
        
    def on_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            print('connection successful')
            total_info['connection'] = 'success'
            client.found = True
        else:
            total_info['connection'] = 'error code: ' + str(rc)
            client.disconnect()
            client.loop_stop()
        
        client.stop_loop = True

    client = mqtt.Client(client_id='test')


    client.on_connect = on_connect
    client.on_message = on_message

    client.stop_loop = False


    try:
        client.loop_start()

        client.connect(domain, port)

        #wait till the client is connected
        time.sleep(3)

        do_system_info(client)

        time.sleep(7)

        total_info['system_info'] = system_info
        
        time.sleep(1)

        print('discovery')
        discovery(client)

        time.sleep(30)

        total_info['discovery'] = message_list

        total_info['unique_topics'] = topic_set

        client.disconnect()

        client.loop_stop()

        return total_info
    
    except:
        print('The connection timed out')
        client.loop_stop()
        return -1

sys.modules[__name__] = mqtt_connect