# CA Server (Project 3 – tuần 5)

FastAPI + SQLite + `cryptography`. Cấp chứng thư X.509 cho thiết bị từ CSR.

## Cấu trúc
- `app/pki.py`   – kiểm tra CSR, ký chứng thư (logic PKI)
- `app/db.py`    – schema SQLite (`devices`, `certificates` có sẵn cột `status` cho tuần 9)
- `app/main.py`  – REST API: `POST /cert/enroll`, `GET /cert/ca`, `GET /health`
- `provision.py` – đăng ký thiết bị + sinh enrollment token dùng 1 lần
- `tests/`       – 8 test (pytest)

## Chạy
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1) Chép root CA tuần 1 vào pki/ (EC P-256, PEM, key không mật khẩu)
cp <root-ca>.crt pki/ca.crt && cp <root-ca>.key pki/ca.key

# 2) Đăng ký thiết bị -> in ra token
python provision.py device-a

# 3) Chạy CA
uvicorn asgi:app --port 8000

# 4) Giả lập thiết bị bằng openssl + curl
openssl ecparam -name prime256v1 -genkey -noout -out device-a.key
openssl req -new -key device-a.key -subj "/CN=device-a" -out device-a.csr
python3 - GhAgaLqyVNpbEu4Cfuu4Z5a9iCYd9n11 <<'PY' > req.json
import json,sys
print(json.dumps({"device_id":"device-a","token":sys.argv[1],"csr_pem":open("device-a.csr").read()}))
PY
curl -s -X POST localhost:8000/cert/enroll -H 'content-type: application/json' -d @req.json > resp.json
python3 -c "import json;open('device-a.crt','w').write(json.load(open('resp.json'))['certificate_pem'])"
openssl verify -CAfile pki/ca.crt device-a.crt
```

## Test
```bash
python -m pytest -q
```

## Chính sách CA (ghi vào báo cáo)
- Xác thực bootstrap: `device_id` + token dùng 1 lần (lưu SHA-256, so sánh constant-time).
- CSR: chữ ký hợp lệ (proof-of-possession), khóa ECDSA P-256 hoặc Ed25519, CN == device_id.
- CA tự đặt extension (CA:false, digitalSignature, clientAuth, CRL DP); bỏ qua extension thiết bị xin.
- Serial ngẫu nhiên 159-bit; hiệu lực mặc định 30 ngày (`CERT_DAYS`).

## Hạn chế đã biết (để lại cho các tuần sau)
- API đang chạy HTTP; token bootstrap nên đi qua TLS -> bật `--ssl-keyfile/--ssl-certfile` hoặc đặt trong mạng Docker nội bộ và ghi rõ trong threat model.
- Ký trực tiếp bằng root CA; nếu dư thời gian tách intermediate CA.
- Chưa có `/cert/crl` và revoke (tuần 9).
