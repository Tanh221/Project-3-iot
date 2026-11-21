# Tuần 5 – Cài đặt CA và cấp phát chứng thư số

Project 3: Bảo mật dữ liệu cho giao tiếp Device-to-Device (M2M) trong IoT.
Phạm vi: phần C1 của kế hoạch – "CA và cấp phát chứng thư số".

## 1. Mục tiêu

Dựng một CA (Certificate Authority) nhỏ dưới dạng REST API, có khả năng:

- nhận CSR (PKCS#10) từ thiết bị giả lập,
- kiểm tra CSR và danh tính thiết bị,
- ký chứng thư X.509 bằng khóa của root CA (đã tạo ở tuần 1–2 bằng OpenSSL),
- lưu thông tin chứng thư đã cấp vào SQLite.

Kết quả cần có theo kế hoạch: *CA cấp được chứng thư cho thiết bị giả lập*.

## 2. Công nghệ

| Thành phần | Lựa chọn | Ghi chú |
|---|---|---|
| Ngôn ngữ / framework | Python, FastAPI + Uvicorn | REST API, tự sinh tài liệu tại `/docs` |
| Thư viện mật mã | `cryptography` | Parse CSR, dựng và ký X.509 (không gọi `openssl` bằng subprocess) |
| Lưu trữ | SQLite | Bảng `devices`, `certificates` |
| Triển khai | Docker Compose, service `ca` | Cùng mạng `iotnet` với broker và thiết bị |
| Root CA | EC P-256, tạo bằng OpenSSL ở tuần 1 | Đọc từ `certs/ca.crt`, `certs/ca.key` |

## 3. Thiết kế

### 3.1 Luồng enrollment (khớp diagram "Enrollment")

1. Thiết bị sinh khóa (ECDSA P-256 hoặc Ed25519).
2. Thiết bị tạo CSR PKCS#10, `CN = device_id`.
3. Thiết bị gửi `POST /cert/enroll` kèm `device_id`, enrollment token và CSR.
4. CA xác thực bước bootstrap (device_id + token) và kiểm tra CSR.
5. CA ký chứng thư X.509.
6. CA lưu metadata chứng thư vào SQLite và đánh dấu thiết bị đã enroll.
7. CA trả về chứng thư và chuỗi tin cậy (root CA).

### 3.2 API

| Method | Đường dẫn | Mô tả |
|---|---|---|
| POST | `/cert/enroll` | Nhận `{device_id, token, csr_pem}`, trả `{serial, certificate_pem, chain_pem}` |
| GET | `/cert/ca` | Trả chứng thư root CA (PEM) |
| GET | `/health` | Kiểm tra sống (dùng cho healthcheck của Docker) |

Mã lỗi của `/cert/enroll`:

| Mã | Ý nghĩa |
|---|---|
| 401 | `device_id` hoặc token sai. Cùng một thông báo cho "không tồn tại" và "sai token" để tránh dò tên thiết bị |
| 400 | CSR không hợp lệ theo chính sách |
| 409 | Thiết bị đã enroll (token chỉ dùng một lần) |

### 3.3 Chính sách của CA

**Xác thực bước bootstrap.** Mỗi thiết bị được đăng ký trước bằng `provision.py`, script này sinh enrollment token ngẫu nhiên dùng một lần. CA chỉ lưu SHA-256 của token và so sánh bằng `hmac.compare_digest` (constant-time). Token được đưa cho thiết bị ngoài băng (biến môi trường). Bước này bổ sung chỗ còn thiếu của diagram ban đầu ("Validate CSR and Identity" chưa nói CA xác thực thiết bị bằng gì).

**Kiểm tra CSR:**

- chữ ký của CSR hợp lệ (proof-of-possession: thiết bị thật sự giữ khóa riêng);
- khóa công khai là ECDSA P-256 hoặc Ed25519 (RSA bị từ chối);
- `CN` đúng bằng `device_id` và chỉ có một CN.

**Chống đua (race).** Việc đánh dấu `enrolled = 1` dùng `UPDATE ... WHERE enrolled = 0` và kiểm tra `rowcount`, nên hai request đồng thời với cùng một token chỉ có một request thành công.

**CA tự quyết định nội dung chứng thư**, bỏ qua mọi extension mà thiết bị yêu cầu trong CSR.

### 3.4 Mẫu chứng thư thiết bị

| Trường / extension | Giá trị |
|---|---|
| Subject | `O = Project3 IoT, CN = <device_id>` |
| Serial | Số ngẫu nhiên 159-bit, dương (lưu dạng hex) |
| Hiệu lực | 30 ngày (`CERT_DAYS`), `notBefore` sớm hơn lúc cấp 1 phút để chừa lệch đồng hồ |
| BasicConstraints | `CA:FALSE` (critical) |
| KeyUsage | `digitalSignature` (critical) |
| ExtendedKeyUsage | `clientAuth` |
| SubjectAltName | `DNS:<device_id>` |
| Subject/Authority Key Identifier | Có |
| CRL Distribution Points | `http://ca:8000/cert/crl` (chuẩn bị cho tuần 9) |
| Thuật toán ký | ECDSA-SHA256 (theo khóa root CA) |

### 3.5 SQLite Db

```sql
CREATE TABLE devices (
    device_id   TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL,              -- SHA-256 của enrollment token
    enrolled    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE certificates (
    serial      TEXT PRIMARY KEY,           -- hex
    device_id   TEXT NOT NULL REFERENCES devices(device_id),
    subject     TEXT NOT NULL,
    not_before  TEXT NOT NULL,              -- ISO 8601, UTC
    not_after   TEXT NOT NULL,
    fingerprint TEXT NOT NULL,              -- SHA-256 của DER
    pem         TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE | REVOKED
    revoked_at  TEXT
);
```

Cột `status` và `revoked_at` đã có sẵn để tuần 9 làm thu hồi chứng thư.

## 4. Cấu trúc mã nguồn

```
ca/
├── app/
│   ├── config.py     # cấu hình qua biến môi trường
│   ├── db.py         # schema SQLite, băm và so sánh token
│   ├── pki.py        # kiểm tra CSR, ký chứng thư X.509
│   └── main.py       # REST API (FastAPI)
├── tests/test_enroll.py
├── asgi.py           # điểm vào của uvicorn
├── provision.py      # đăng ký thiết bị + sinh token dùng một lần
├── Dockerfile
└── requirements.txt
```

Biến môi trường: `CA_CERT_PATH`, `CA_KEY_PATH`, `CA_DB_PATH`, `CERT_DAYS`, `CRL_URL`.

## 5. Triển khai và cách chạy

Service `ca` trong `docker-compose.yml`:

- build từ `./ca`, cổng `8000`, thuộc mạng `iotnet` (hostname `ca`);
- mount `certs/ca.crt` và `certs/ca.key` ở chế độ chỉ đọc, mount `ca/data` để giữ `ca.db`;
- có healthcheck gọi `/health`.

Đăng ký thiết bị và lấy token:

```bash
docker compose exec ca python provision.py device-a
```

Giả lập thiết bị thủ công bằng OpenSSL + curl (cách đã kiểm chứng trước khi viết client ở tuần 6):

```bash
openssl ecparam -name prime256v1 -genkey -noout -out device-a.key
openssl req -new -key device-a.key -subj "/CN=device-a" -out device-a.csr
# gửi JSON {device_id, token, csr_pem} tới POST /cert/enroll, lấy certificate_pem
openssl verify -CAfile certs/ca.crt device-a.crt
```

## 6. Kiểm thử

Bộ test `pytest` gồm 8 test, tất cả đạt:

| Test | Nội dung kiểm tra |
|---|---|
| enroll thành công | Chữ ký CA hợp lệ, issuer đúng, `CA:FALSE`, có CRL DP; `openssl verify` ra OK; DB có dòng `ACTIVE` |
| Ed25519 | Khóa Ed25519 được chấp nhận |
| token sai / thiết bị không tồn tại | Cùng mã 401, cùng nội dung lỗi |
| CN không khớp | 400 |
| khóa RSA | 400 |
| chữ ký CSR bị sửa | 400 (proof-of-possession) |
| token một lần | Lần enroll thứ hai trả 409 |
| `GET /cert/ca` | Trả PEM của root CA |

Kiểm thử thủ công với root CA thật của project: `openssl verify -CAfile certs/ca.crt device-a.crt` cho kết quả `OK`; enroll lần hai với cùng token trả 409; bảng `certificates` ghi nhận chứng thư `ACTIVE`.

## 7. Kết quả

CA chạy trong Docker, cấp được chứng thư X.509 cho thiết bị qua REST API; chuỗi tin cậy xác minh được bằng OpenSSL; metadata được lưu trong SQLite. Đạt mục tiêu của tuần 5.

## 8. Hạn chế và việc cho các tuần sau

| Hạn chế | Kế hoạch |
|---|---|
| API chạy HTTP trong mạng Docker nội bộ, token bootstrap đi không mã hóa | Bật TLS cho CA, hoặc ghi rõ giả định mạng nội bộ trong threat model |
| CA ký trực tiếp bằng root CA | Tách intermediate CA nếu còn thời gian |
| Tên endpoint `/cert/enroll` không theo đúng EST (RFC 7030) | Gọi là "EST-inspired" trong báo cáo, hoặc đổi sang `/.well-known/est/simpleenroll` và trả PKCS#7 |
| `provision.py` đặt lại cờ `enrolled` nhưng không thu hồi chứng thư cũ, nên một thiết bị có thể có nhiều chứng thư `ACTIVE` | Tuần 9: khi enroll lại, tự chuyển chứng thư cũ sang `REVOKED` và đưa vào CRL |
| Chưa có `/cert/crl` và API revoke | Tuần 9 |
| Token đưa qua biến môi trường / file `.env` | Chấp nhận được cho mô phỏng; ngoài thực tế dùng secret manager |


