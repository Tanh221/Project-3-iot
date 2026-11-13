import re
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")


class CSRError(ValueError):
    """CSR không hợp lệ theo chính sách của CA."""


def load_ca(cert_path: str, key_path: str):
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return cert, key


def parse_csr(pem: str, device_id: str) -> x509.CertificateSigningRequest:
    """Kiểm tra CSR: PoP (chữ ký CSR), loại khóa, CN khớp device_id."""
    if not DEVICE_ID_RE.match(device_id):
        raise CSRError("device_id không hợp lệ")
    try:
        csr = x509.load_pem_x509_csr(pem.encode())
    except ValueError:
        raise CSRError("CSR không parse được (cần PEM PKCS#10)")

    if not csr.is_signature_valid:  # proof-of-possession
        raise CSRError("Chữ ký CSR không hợp lệ")

    pub = csr.public_key()
    ok_ec = isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name == "secp256r1"
    if not (ok_ec or isinstance(pub, ed25519.Ed25519PublicKey)):
        raise CSRError("Chỉ chấp nhận ECDSA P-256 hoặc Ed25519")

    cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cns) != 1 or cns[0].value != device_id:
        raise CSRError("CN của CSR phải đúng bằng device_id")
    return csr


def sign_csr(csr, ca_cert, ca_key, device_id: str, days: int, crl_url: str) -> x509.Certificate:
    """CA tự quyết định extension; bỏ qua extension do thiết bị yêu cầu."""
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Project3 IoT"),
        x509.NameAttribute(NameOID.COMMON_NAME, device_id),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(secrets.randbits(159) | (1 << 158))  # dương, ngẫu nhiên, khó đoán
        .not_valid_before(now - timedelta(minutes=1))       # chừa lệch đồng hồ
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(device_id)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False)
        .add_extension(
            x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_url)],
                relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
    )
    algo = None if isinstance(ca_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(ca_key, algo)


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()
