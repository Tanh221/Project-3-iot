import hashlib
import hmac
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL,           -- SHA-256 của enrollment token (dùng 1 lần)
    enrolled    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS certificates (
    serial      TEXT PRIMARY KEY,        -- hex
    device_id   TEXT NOT NULL REFERENCES devices(device_id),
    subject     TEXT NOT NULL,
    not_before  TEXT NOT NULL,           -- ISO 8601 UTC
    not_after   TEXT NOT NULL,
    fingerprint TEXT NOT NULL,           -- SHA-256 của DER
    pem         TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'ACTIVE',   -- ACTIVE | REVOKED
    revoked_at  TEXT
);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path: str) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def token_matches(stored_hash: str, token: str) -> bool:
    return hmac.compare_digest(stored_hash, hash_token(token))
