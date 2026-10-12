"""Client MQTT mẫu.
Chạy:  python device/mqtt_client.py sub device-a          (mTLS, cổng 8883)
       python device/mqtt_client.py pub device-b          (mTLS, cổng 8883)
       python device/mqtt_client.py pub device-b plain    (KHÔNG mã hóa, cổng 1883, chỉ để demo)
"""
import ssl
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt

role, name = sys.argv[1], sys.argv[2]
mode = sys.argv[3] if len(sys.argv) > 3 else "tls"
CERTS = Path(__file__).resolve().parent.parent / "certs"
TOPIC = "project3/sensor"


def on_connect(client, userdata, flags, reason_code, properties):
    print(f"[{name}] kết nối broker ({mode}): {reason_code}")
    if role == "sub":
        client.subscribe(TOPIC)


def on_message(client, userdata, msg):
    print(f"[{name}] nhận: {msg.topic} = {msg.payload.decode()}")


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=name)
client.on_connect = on_connect
client.on_message = on_message

if mode == "tls":
    # Nạp CA (để tin broker) + chứng thư và khóa riêng của thiết bị
    client.tls_set(
        ca_certs=str(CERTS / "ca.crt"),
        certfile=str(CERTS / f"{name}.crt"),
        keyfile=str(CERTS / f"{name}.key"),
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )
    port = 8883
else:
    port = 1883

client.connect("localhost", port)

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
