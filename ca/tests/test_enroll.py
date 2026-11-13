import datetime
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app import db
from app.config import Settings
from app.main import create_app


def make_root(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    (tmp_path / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "ca.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return cert


def make_csr(cn, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    algo = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
           .sign(key, algo))
    return csr.public_bytes(serialization.Encoding.PEM).decode(), key


@pytest.fixture
def env(tmp_path):
    root = make_root(tmp_path)
    s = Settings(ca_cert_path=str(tmp_path / "ca.crt"), ca_key_path=str(tmp_path / "ca.key"),
                 db_path=str(tmp_path / "ca.db"), cert_days=30, crl_url="http://ca:8000/cert/crl")
    client = TestClient(create_app(s))

    def provision(dev, token="tok-" + "x" * 20):
        with db.connect(s.db_path) as c:
            c.execute("INSERT OR REPLACE INTO devices VALUES (?,?,0)", (dev, db.hash_token(token)))
        return token
    return client, root, s, provision, tmp_path


def post(client, dev, token, csr):
    return client.post("/cert/enroll", json={"device_id": dev, "token": token, "csr_pem": csr})


def test_enroll_ok_and_chain_valid(env):
    client, root, s, provision, tmp = env
    tok = provision("device-a")
    csr, _ = make_csr("device-a")
    r = post(client, "device-a", tok, csr)
    assert r.status_code == 200, r.text
    cert = x509.load_pem_x509_certificate(r.json()["certificate_pem"].encode())
    # chữ ký của CA hợp lệ
    root.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    assert cert.issuer == root.subject
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    # openssl cũng xác minh được (giống cách bạn làm ở tuần 2)
    (tmp / "dev.crt").write_text(r.json()["certificate_pem"])
    out = subprocess.run(["openssl", "verify", "-CAfile", str(tmp / "ca.crt"), str(tmp / "dev.crt")],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr + out.stdout
    # đã lưu SQLite
    with db.connect(s.db_path) as c:
        row = c.execute("SELECT status, device_id FROM certificates").fetchone()
    assert (row["status"], row["device_id"]) == ("ACTIVE", "device-a")


def test_ed25519_accepted(env):
    client, _, _, provision, _ = env
    tok = provision("device-b")
    csr, _ = make_csr("device-b", ed25519.Ed25519PrivateKey.generate())
    assert post(client, "device-b", tok, csr).status_code == 200


def test_wrong_token_and_unknown_device_same_error(env):
    client, _, _, provision, _ = env
    provision("device-a")
    csr, _ = make_csr("device-a")
    r1 = post(client, "device-a", "sai-token", csr)
    r2 = post(client, "khong-ton-tai", "sai-token", csr)
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json()


def test_cn_mismatch_rejected(env):
    client, _, _, provision, _ = env
    tok = provision("device-a")
    csr, _ = make_csr("device-z")
    assert post(client, "device-a", tok, csr).status_code == 400


def test_rsa_rejected(env):
    client, _, _, provision, _ = env
    tok = provision("device-a")
    csr, _ = make_csr("device-a", rsa.generate_private_key(65537, 2048))
    assert post(client, "device-a", tok, csr).status_code == 400


def test_tampered_csr_signature_rejected(env):
    client, _, _, provision, _ = env
    tok = provision("device-a")
    csr_pem, _ = make_csr("device-a")
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01
    bad = x509.load_der_x509_csr(bytes(der))
    bad_pem = bad.public_bytes(serialization.Encoding.PEM).decode()
    r = post(client, "device-a", tok, bad_pem)
    assert r.status_code == 400


def test_token_is_one_time(env):
    client, _, _, provision, _ = env
    tok = provision("device-a")
    csr, _ = make_csr("device-a")
    assert post(client, "device-a", tok, csr).status_code == 200
    csr2, _ = make_csr("device-a")
    assert post(client, "device-a", tok, csr2).status_code == 409


def test_get_ca(env):
    client, root, *_ = env
    r = client.get("/cert/ca")
    assert r.status_code == 200 and "BEGIN CERTIFICATE" in r.text
