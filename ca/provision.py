"""Đăng ký thiết bị + tạo enrollment token dùng 1 lần.
Dùng:  python provision.py device-a
"""
import secrets
import sys

from app import db
from app.config import Settings
from app.pki import DEVICE_ID_RE

if len(sys.argv) != 2 or not DEVICE_ID_RE.match(sys.argv[1]):
    sys.exit("Usage: python provision.py <device_id>   (3-64 ký tự: chữ, số, _ , -)")

device_id = sys.argv[1]
s = Settings()
db.init_db(s.db_path)
token = secrets.token_urlsafe(24)
with db.connect(s.db_path) as conn:
    # INSERT OR REPLACE: provision lại = reset để enroll lần nữa
    conn.execute(
        "INSERT OR REPLACE INTO devices (device_id, token_hash, enrolled) VALUES (?, ?, 0)",
        (device_id, db.hash_token(token)))
print(f"device_id = {device_id}\ntoken     = {token}\n(token chỉ hiện một lần, hãy đưa vào env của container thiết bị)")
