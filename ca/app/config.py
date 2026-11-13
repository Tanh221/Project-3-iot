import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    ca_cert_path: str = os.getenv("CA_CERT_PATH", "pki/ca.crt")
    ca_key_path: str = os.getenv("CA_KEY_PATH", "pki/ca.key")
    db_path: str = os.getenv("CA_DB_PATH", "data/ca.db")
    cert_days: int = int(os.getenv("CERT_DAYS", "30"))
    # URL phát hành CRL, nhúng vào chứng thư (khớp GET /cert/crl ở diagram thu hồi)
    crl_url: str = os.getenv("CRL_URL", "http://ca:8000/cert/crl")
