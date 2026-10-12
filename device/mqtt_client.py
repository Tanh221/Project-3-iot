"""Client MQTT mẫu: kết nối broker bằng mTLS.
Chạy:  python device/mqtt_client.py sub device-a
       python device/mqtt_client.py pub device-b
"""
import ssl
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt

role, name = sys.argv[1], sys.argv[2]          # sub/pub và tên thiết bị
CERTS = Path(__file__).resolve().parent.parent / "certs"
TOPIC = "project3/sensor"


def on_connect(client, userdata, flags, reason_code, properties):
    print(f"[{name}] kết nối broker: {reason_code}")
    if role == "sub":
        client.subscribe(TOPIC)


def on_message(client, userdata, msg):
    print(f"[{name}] nhận: {msg.topic} = {msg.payload.decode()}")


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=name)
client.on_connect = on_connect
client.on_message = on_message

# Dòng quan trọng nhất: nạp CA (để tin broker) + chứng thư và khóa riêng của thiết bị
client.tls_set(
    ca_certs=str(CERTS / "ca.crt"),
    certfile=str(CERTS / f"{name}.crt"),
    keyfile=str(CERTS / f"{name}.key"),
    tls_version=ssl.PROTOCOL_TLS_CLIENT,
)
client.connect("localhost", 8883)

if role == "sub":
    client.loop_forever()
else:
    client.loop_start()
    time.sleep(1)
    for i in range(1, 6):
        payload = f"temp={20 + i}.5C seq={i}"
        client.publish(TOPIC, payload, qos=1).wait_for_publish()
        print(f"[{name}] gửi: {payload}")
        time.sleep(1)
    client.loop_stop()
    client.disconnect()
