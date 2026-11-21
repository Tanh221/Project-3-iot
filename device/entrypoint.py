"""Entrypoint của container thiết bị: enroll (nếu chưa có chứng thư) rồi chạy lệnh chính.

Docker: ENTRYPOINT ["python", "entrypoint.py"]  +  command: ["python", "mqtt_client.py", "sub", "device-a"]
Biến môi trường: DEVICE_ID, ENROLL_TOKEN, CA_URL, CA_CERT_PATH (root CA đã ghim), DATA_DIR.
"""
import os
import sys

from pki_client import EnrollError, ensure_enrolled

device_id = os.environ["DEVICE_ID"]
data_dir = os.getenv("DATA_DIR", "/data")

try:
    ensure_enrolled(
        device_id=device_id,
        token=os.getenv("ENROLL_TOKEN", ""),
        ca_url=os.getenv("CA_URL", "http://ca:8000"),
        ca_cert_path=os.getenv("CA_CERT_PATH", "/pinned/ca.crt"),
        data_dir=data_dir,
    )
except EnrollError as e:
    sys.exit(f"[{device_id}] LỖI enroll: {e}")

# mqtt_client.py nạp ca.crt, <tên>.crt, <tên>.key từ CERT_DIR
os.environ.setdefault("CERT_DIR", data_dir)

if len(sys.argv) < 2:
    sys.exit("thiếu lệnh để chạy sau khi enroll")
os.execvp(sys.argv[1], sys.argv[1:])