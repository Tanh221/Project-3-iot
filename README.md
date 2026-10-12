# Project 3: Bảo mật dữ liệu cho giao tiếp D2D/M2M trong IoT

Hệ thống giả lập: broker MQTT (Mosquitto) + 2 thiết bị (Docker Compose),
kết nối bằng TLS + xác thực hai chiều (mTLS) với chứng thư do root CA tự tạo.

## Cấu trúc
- broker/   cấu hình Mosquitto (1883 không mã hóa để demo, 8883 mTLS)
- device/   client thiết bị giả lập (Python, paho-mqtt) + Dockerfile
- certs/    khóa và chứng thư (KHÔNG commit, đã nằm trong .gitignore)
- captures/ file .pcap bắt gói tin (KHÔNG commit)
- docs/     ảnh chụp Wireshark, ghi chú

## Tạo chứng thư (làm tay bằng OpenSSL, tuần 1)
Root CA, chứng thư broker (serverAuth, SAN) và device-a/device-b (clientAuth).
Các lệnh nằm trong docs/week1-notes.md.

## Chạy
    docker compose up --build
    docker compose down
