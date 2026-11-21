"""Tuần 6: thiết bị tự sinh khóa, tạo CSR, enroll với CA và lưu chứng thư.

Dùng thử trên máy (đứng ở thư mục device/):
  CA_URL=http://localhost:8000 CA_CERT_PATH=../certs/ca.crt \
  DEVICE_ID=device-a ENROLL_TOKEN=<token> DATA_DIR=enrolled-test \
  python pki_client.py
"""
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class EnrollError(Exception):
    """Enroll thất bại (CA từ chối, không kết nối được, hoặc cert trả về không hợp lệ)."""


# ---------- Bước 1: khóa + CSR ----------
def generate_keypair() -> ec.EllipticCurvePrivateKey:
    """Khóa ECDSA P-256 (khớp chính sách CA: P-256 hoặc Ed25519)."""
    return ec.generate_private_key(ec.SECP256R1())


def build_csr(key: ec.EllipticCurvePrivateKey, device_id: str) -> str:
    """CSR PKCS10, CN = device_id, ký bằng chính khóa riêng (proof-of-possession)."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def save_private_key(key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    """Lưu khóa riêng với quyền 0600 (chỉ chủ sở hữu đọc được)."""
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


# ---------- Bước 2: enroll + kiểm tra + lưu ----------
def enroll(ca_url: str, device_id: str, token: str, csr_pem: str, retries: int = 30) -> dict:
    """POST /cert/enroll. CA có thể chưa sẵn sàng nên thử lại tối đa `retries` giây."""
    body = json.dumps({"device_id": device_id, "token": token, "csr_pem": csr_pem}).encode()
    req = urllib.request.Request(
        f"{ca_url.rstrip('/')}/cert/enroll",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    for _ in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:  # CA trả lỗi: không thử lại
            try:
                detail = json.load(e).get("detail", "")
            except Exception:
                detail = ""
            raise EnrollError(f"CA từ chối ({e.code}): {detail}")
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            print(f"[enroll] chờ CA ({e})", flush=True)
            time.sleep(1)
    raise EnrollError(f"không kết nối được CA {ca_url}")


def verify_issued_cert(cert_pem: str, key, ca_pem: str, device_id: str) -> None:
    """ kiểm tra cert nhận về đúng là của mình và do root CA đã ghim ký."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    ca = x509.load_pem_x509_certificate(ca_pem.encode())
    if cert.issuer != ca.subject:
        raise EnrollError("issuer của cert không khớp root CA đã ghim")
    try:
        ca.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm)
        )
    except Exception:
        raise EnrollError("chữ ký CA trên cert không hợp lệ")
    pub = lambda k: k.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if pub(cert.public_key()) != pub(key.public_key()):
        raise EnrollError("cert không chứa khóa công khai của thiết bị này")
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cns) != 1 or cns[0].value != device_id:
        raise EnrollError("CN của cert không khớp device_id")
    now = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise EnrollError("cert chưa có hiệu lực hoặc đã hết hạn")


def ensure_enrolled(device_id: str, token: str, ca_url: str, ca_cert_path: str, data_dir: str) -> None:
    """Nếu thiết bị đã có khóa + cert thì bỏ qua; chưa có thì enroll rồi lưu vào data_dir."""
    d = Path(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    key_path, crt_path, ca_path = d / f"{device_id}.key", d / f"{device_id}.crt", d / "ca.crt"

    if key_path.exists() and crt_path.exists():
        print(f"[{device_id}] đã có chứng thư, bỏ qua enroll", flush=True)
        shutil.copyfile(ca_cert_path, ca_path)
        return
    if not token:
        raise EnrollError("chưa có chứng thư và ENROLL_TOKEN đang trống")

    pinned_ca = Path(ca_cert_path).read_text()
    key = generate_keypair()
    result = enroll(ca_url, device_id, token, build_csr(key, device_id))
    verify_issued_cert(result["certificate_pem"], key, pinned_ca, device_id)

    # Chỉ ghi ra đĩa sau khi mọi kiểm tra đã qua
    save_private_key(key, key_path)
    crt_path.write_text(result["certificate_pem"])
    ca_path.write_text(pinned_ca)
    print(f"[{device_id}] enroll thành công, serial={result['serial'][:12]}…", flush=True)


if __name__ == "__main__":
    try:
        ensure_enrolled(
            device_id=os.environ["DEVICE_ID"],
            token=os.getenv("ENROLL_TOKEN", ""),
            ca_url=os.getenv("CA_URL", "http://localhost:8000"),
            ca_cert_path=os.environ["CA_CERT_PATH"],
            data_dir=os.getenv("DATA_DIR", "enrolled-test"),
        )
    except (KeyError, EnrollError) as e:
        sys.exit(f"LỖI: {e}")