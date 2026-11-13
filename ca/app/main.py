from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from . import db, pki
from .config import Settings


class EnrollRequest(BaseModel):
    device_id: str
    token: str          # enrollment token cấp ngoài băng (provision.py)
    csr_pem: str


class EnrollResponse(BaseModel):
    serial: str
    certificate_pem: str
    chain_pem: list[str]   # [Root CA]


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def create_app(settings: Settings | None = None) -> FastAPI:
    s = settings or Settings()
    db.init_db(s.db_path)
    ca_cert, ca_key = pki.load_ca(s.ca_cert_path, s.ca_key_path)
    app = FastAPI(title="Project3 CA")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/cert/ca", response_class=PlainTextResponse)
    def get_ca():
        return pki.cert_pem(ca_cert)

    @app.post("/cert/enroll", response_model=EnrollResponse)
    def enroll(req: EnrollRequest):
        # 1) Xác thực bước bootstrap: device_id + token. Cùng một lỗi cho "không tồn tại" và "sai token".
        with db.connect(s.db_path) as conn:
            row = conn.execute(
                "SELECT token_hash, enrolled FROM devices WHERE device_id = ?",
                (req.device_id,)).fetchone()
        if row is None or not db.token_matches(row["token_hash"], req.token):
            raise HTTPException(401, "device_id hoặc token không đúng")
        if row["enrolled"]:
            raise HTTPException(409, "Thiết bị đã enroll; cần provision lại để enroll lần nữa")

        # 2) Kiểm tra CSR theo chính sách
        try:
            csr = pki.parse_csr(req.csr_pem, req.device_id)
        except pki.CSRError as e:
            raise HTTPException(400, str(e))

        # 3) Ký chứng thư
        cert = pki.sign_csr(csr, ca_cert, ca_key, req.device_id, s.cert_days, s.crl_url)
        serial = format(cert.serial_number, "x")

        # 4) Lưu DB; UPDATE có điều kiện enrolled=0 để chặn 2 request đồng thời
        with db.connect(s.db_path) as conn:
            cur = conn.execute(
                "UPDATE devices SET enrolled = 1 WHERE device_id = ? AND enrolled = 0",
                (req.device_id,))
            if cur.rowcount != 1:
                raise HTTPException(409, "Thiết bị đã enroll")
            conn.execute(
                "INSERT INTO certificates (serial, device_id, subject, not_before, not_after,"
                " fingerprint, pem) VALUES (?,?,?,?,?,?,?)",
                (serial, req.device_id, cert.subject.rfc4514_string(),
                 _iso(cert.not_valid_before_utc), _iso(cert.not_valid_after_utc),
                 cert.fingerprint(hashes.SHA256()).hex(), pki.cert_pem(cert)))

        return EnrollResponse(
            serial=serial, certificate_pem=pki.cert_pem(cert),
            chain_pem=[pki.cert_pem(ca_cert)])

    return app
