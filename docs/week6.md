# Tuần 6 – Client thiết bị tự enroll với CA

Project 3: Bảo mật dữ liệu cho giao tiếp Device-to-Device (M2M) trong IoT.
Phạm vi: phần C1 (tiếp theo) – "Cài đặt client thiết bị (container Python): sinh khóa, tạo CSR, enrollment với CA, lưu chứng thư".

## 1. Mục tiêu

Mỗi thiết bị giả lập (container Docker) tự thực hiện toàn bộ quy trình enrollment khi khởi động, không cần cấp chứng thư bằng tay như tuần 1–2:

- sinh khóa riêng ngay trên thiết bị;
- tạo CSR và gửi cho CA;
- kiểm tra chứng thư nhận về;
- lưu khóa và chứng thư vào nơi lưu trữ riêng của thiết bị;
- dùng chứng thư đó để kết nối broker bằng mTLS.

Kết quả cần có theo kế hoạch: *thiết bị tự enroll thành công*.

## 2. Thiết kế

### 2.1 Luồng khi container khởi động

```
entrypoint.py
   ├─ đã có <id>.key và <id>.crt trong /data ?
   │      ├─ có   → bỏ qua enroll
   │      └─ chưa → cần ENROLL_TOKEN
   │               1. sinh khóa ECDSA P-256 (trong bộ nhớ)
   │               2. tạo CSR (CN = device_id), ký bằng khóa riêng
   │               3. POST /cert/enroll (device_id, token, CSR)
   │               4. kiểm tra chứng thư nhận về
   │               5. ghi <id>.key (0600), <id>.crt, ca.crt vào /data
   └─ chạy lệnh chính: mqtt_client.py (mTLS, nạp cert từ CERT_DIR=/data)
```

### 2.2 Các quyết định thiết kế

**Khóa riêng sinh trên thiết bị và không rời thiết bị.** CA chỉ nhận CSR chứa khóa công khai nên không bao giờ biết khóa riêng. File khóa được ghi với quyền `0600`.

**Ghim (pin) root CA.** Thiết bị không tin `ca.crt` do CA trả về qua HTTP, mà dùng bản root CA công khai được mount sẵn (`CA_CERT_PATH=/pinned/ca.crt`). Nếu không, kẻ nghe lén trên đường HTTP có thể thay bằng CA giả và lừa thiết bị chấp nhận chứng thư của hắn.

**Kiểm tra chứng thư nhận về** trước khi lưu:

| Kiểm tra | Mục đích |
|---|---|
| `issuer` khớp subject của root CA đã ghim | Đúng CA |
| Chữ ký CA trên chứng thư hợp lệ | Không bị giả mạo |
| Khóa công khai trong cert trùng khóa của thiết bị | Cert thật sự là của mình |
| `CN` bằng `device_id` | Đúng danh tính |
| Còn trong thời hạn hiệu lực | Không nhận cert hết hạn |

**Chỉ ghi ra đĩa sau khi mọi kiểm tra đã qua**, nên không để lại khóa riêng mà không có chứng thư hợp lệ.

**Idempotent.** Khi container khởi động lại và đã có khóa + chứng thư trong volume, thiết bị bỏ qua enroll và không cần token nữa. Token chỉ phục vụ lần chạy đầu tiên.

**Chờ CA sẵn sàng.** Hàm enroll thử lại tối đa 30 giây khi chưa kết nối được CA (lỗi mạng). Lỗi do CA trả về (401, 400, 409) thì dừng ngay, không thử lại.

### 2.3 Cải thiện bảo mật: tách lưu trữ khóa theo từng thiết bị

Trước đây cả hai thiết bị mount nguyên thư mục `./certs`, trong đó có `ca.key` và khóa của thiết bị kia. Như vậy một thiết bị bị chiếm quyền sẽ lấy được khóa root CA, trái với kịch bản "thiết bị bị đánh cắp" trong threat model.

Sau tuần 6:

| Thành phần | Mount |
|---|---|
| Thiết bị | `./certs/ca.crt` → `/pinned/ca.crt` (chỉ đọc, công khai) và volume riêng `device-x-data` → `/data` |
| CA | `certs/ca.crt` và `certs/ca.key` (chỉ đọc) |
| Broker | `./certs` (chỉ đọc) |

Thiết bị không còn truy cập được `ca.key` hay khóa của thiết bị khác.

## 3. Mã nguồn

```
device/
├── pki_client.py    # sinh khóa, tạo CSR, enroll, kiểm tra cert, lưu file
├── entrypoint.py    # enroll nếu cần, rồi exec lệnh chính
├── mqtt_client.py   # giữ nguyên từ tuần 1–2 (nạp cert từ CERT_DIR)
├── Dockerfile       # ENTRYPOINT ["python", "entrypoint.py"]
└── requirements.txt # paho-mqtt, cryptography
```

Các hàm chính trong `pki_client.py`:

| Hàm | Vai trò |
|---|---|
| `generate_keypair()` | Khóa ECDSA P-256 |
| `build_csr(key, device_id)` | CSR PKCS#10 với `CN = device_id`, tự ký (proof-of-possession) |
| `save_private_key(key, path)` | Ghi PKCS#8 PEM, quyền `0600` |
| `enroll(ca_url, device_id, token, csr_pem)` | `POST /cert/enroll` bằng `urllib` (không thêm thư viện HTTP), có retry khi CA chưa sẵn sàng |
| `verify_issued_cert(...)` | Các kiểm tra ở mục 2.2 |
| `ensure_enrolled(...)` | Gói toàn bộ luồng, idempotent |

`entrypoint.py` đọc `DEVICE_ID`, `ENROLL_TOKEN`, `CA_URL`, `CA_CERT_PATH`, `DATA_DIR`, đặt `CERT_DIR=/data` rồi `exec` lệnh chính. Tên file đầu ra (`<tên>.key`, `<tên>.crt`, `ca.crt`) khớp với cách `mqtt_client.py` nạp cert, nên client MQTT không cần sửa.

## 4. Cấu hình và cách chạy

Token đưa vào thiết bị qua file `.env` (đã nằm trong `.gitignore`):

```
DEVICE_A_TOKEN=...
DEVICE_B_TOKEN=...
```

`docker-compose.yml` truyền cho mỗi thiết bị các biến: `DEVICE_ID`, `ENROLL_TOKEN=${DEVICE_X_TOKEN:-}`, `CA_URL=http://ca:8000`, `CA_CERT_PATH=/pinned/ca.crt`, `DATA_DIR=/data`; `depends_on` đợi `ca` ở trạng thái healthy.

Script `scripts/reprovision.sh` dùng khi muốn enroll lại từ đầu:

1. `provision.py` cho từng thiết bị để lấy token mới (đồng thời đặt lại cờ `enrolled`);
2. ghi token vào `.env`;
3. xóa container và volume dữ liệu của thiết bị (vì cert đã nằm trong volume, restart đơn thuần sẽ bỏ qua enroll);
4. build lại và khởi động hai thiết bị.

## 5. Kiểm thử

**Thử `pki_client.py` với CA thật (đã chạy trên máy, tất cả đạt):**

| Kịch bản | Kết quả |
|---|---|
| Enroll lần đầu | Thành công; ghi `device-x.key` (quyền `-rw-------`), `device-x.crt`, `ca.crt`; `openssl verify` ra OK; `enrolled = 1` |
| Chạy lại khi đã có chứng thư | In "đã có chứng thư, bỏ qua enroll" |
| Token sai | `CA từ chối (401)` |
| Root CA ghim sai (mô phỏng CA giả) | `issuer của cert không khớp root CA đã ghim`; không có file nào được ghi |
| Chưa có chứng thư và token rỗng | Dừng với thông báo lỗi, exit code 1 |

**Chạy trong container (`entrypoint.py`):**

| Kịch bản | Kết quả mong đợi |
|---|---|
| Enroll rồi chạy lệnh chính | `CERT_DIR=/data` chứa `ca.crt`, `<id>.crt`, `<id>.key` |
| Khởi động lại (token rỗng) | Bỏ qua enroll, chạy lệnh chính |

## 6. Kết quả cần xác nhận khi chạy toàn hệ thống

Chạy toàn hệ thống bằng `bash scripts/reprovision.sh` (cấp token mới, xóa volume cũ, build lại và khởi động hai thiết bị). Kết quả quan sát được:
 
| Mục kiểm tra | Kết quả | Bằng chứng |
|---|---|---|
| Thiết bị tự enroll khi khởi động | Đạt (device-a) | Log: `[device-a] enroll thành công, serial=71d64e0faa5b…` |
| Dùng chứng thư do CA cấp để kết nối broker bằng mTLS | Đạt (device-a) | Log: `[device-a] kết nối broker (tls): Success` |
| CA ghi nhận cả hai thiết bị đã enroll | Đạt | Bảng `devices`: `device-a` và `device-b` đều có `enrolled = 1` |
| Token được thay mới sau mỗi lần provision | Đạt | `token_hash` của hai thiết bị khác nhau và khác lần provision trước |
 
Thứ tự trong log đúng như thiết kế: enroll xong mới kết nối broker, và kết nối dùng chính khóa và chứng thư vừa được cấp (lưu trong volume `/data`), không còn dùng cert cấp tay của tuần 1–2.
 
Cờ `enrolled = 1` của `device-b` cho thấy CA đã nhận và ký CSR của thiết bị này. Các mục sau chưa có bằng chứng trong log đã thu thập, cần bổ sung ảnh chụp trước khi đưa vào báo cáo:

Nếu broker từ chối cert mới, nguyên nhân thường là `mosquitto.conf` có ràng buộc gắn với cert cấp tay cũ (`use_identity_as_username`, ACL, `password_file`); xem `docker compose logs broker`.

## 7. Hạn chế 

| Hạn chế | Kế hoạch |
|---|---|
| Giao tiếp với CA qua HTTP trong mạng Docker nội bộ; token đi không mã hóa | Bật HTTPS cho CA, hoặc ghi giả định mạng nội bộ trong threat model |
| Token bootstrap nằm trong biến môi trường / `.env` | Chấp nhận cho mô phỏng; thực tế dùng secret manager |
| Chưa có gia hạn chứng thư khi sắp hết hạn (30 ngày) | Tuần 9 (hết hạn và gia hạn) |
| Khóa riêng lưu dạng PEM không mã hóa trong volume | Chấp nhận cho mô phỏng; thiết bị thật dùng secure element hoặc TPM |
| Chứng thư cấp tay của tuần 1–2 (`certs/device-*.crt`) không còn dùng trong luồng chính | Giữ lại để đối chiếu, có thể xóa khi hoàn tất |

