import base64
import hashlib
import os
from contextlib import contextmanager
from datetime import datetime

import oracledb 
import chain
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()
ALERTS = {"SENSOR_FAULT": "MEDIUM", "FEVER": "HIGH"}
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev only
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- DB ----------
def get_db():
    return oracledb.connect(
        user=os.getenv("DB_USER", "mediledger"),
        password=os.getenv("DB_PASS", "mediled123"),
        dsn=os.getenv("DB_DSN", "localhost:1521/freepdb1"),
    )


@contextmanager
def db_conn():
    conn = get_db()
    try:
        yield conn
    finally:
        conn.close()


def cursor_to_dict(cursor, row):
    return {col[0].lower(): val for col, val in zip(cursor.description, row)}


# ---------- Crypto ----------
class Measurement(BaseModel):
    device_id: str
    temperature: float
    timestamp: str          # YYYY-MM-DDTHH:MM:SS
    sensor_status: str
    counter: int            # monotonic, replay protection (signed)
    device_hash: str        # sha256(payload) hex
    signature: str          # base64 DER ECDSA(P-256, SHA256) over payload


def build_payload(device_id, temperature, timestamp, sensor_status, counter) -> bytes:
    """Canonical payload. Device and backend MUST build it identically."""
    return f"{device_id}|{float(temperature):.2f}|{timestamp}|{sensor_status}|{int(counter)}".encode()


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def verify_signature(public_key_pem: str, payload: bytes, signature_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode())
        pub.verify(base64.b64decode(signature_b64), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------- Routes ----------
@app.get("/")
def root():
    return {"status": "MediLedger running"}


@app.post("/measurement")
def receive(m: Measurement):
    # format check (also guarantees DB round-trip of timestamp)
    try:
        datetime.strptime(m.timestamp, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise HTTPException(400, "Bad timestamp format")

    if m.sensor_status not in ("VALID", "FEVER", "SENSOR_FAULT"):
        raise HTTPException(400, "Bad sensor_status")

    temp = round(m.temperature, 2)
    payload = build_payload(m.device_id, temp, m.timestamp, m.sensor_status, m.counter)

    # hash sent by device must match data sent by device
    if sha256_hex(payload) != m.device_hash:
        raise HTTPException(400, "Hash does not match data")

    with db_conn() as db:
        cur = db.cursor()

        cur.execute(
            "SELECT public_key FROM DEVICE WHERE device_id=:1 AND status='ACTIVE'",
            (m.device_id,),
        )
        row = cur.fetchone()
        if not row or not row[0]:
            raise HTTPException(403, "Device not registered")

        # ECDSA: backend holds PUBLIC key only. Cannot sign. Cannot forge.
        if not verify_signature(row[0], payload, m.signature):
            raise HTTPException(401, "Invalid device signature")

        # replay protection
        cur.execute(
            "SELECT NVL(MAX(counter),0) FROM MEASUREMENT WHERE device_id=:1",
            (m.device_id,),
        )
        if m.counter <= cur.fetchone()[0]:
            raise HTTPException(409, "Replay detected (counter not increasing)")

        measurement_id_var = cur.var(int)
        try:
            cur.execute(
                """
                INSERT INTO MEASUREMENT
                  (patient_id, device_id, temperature, timestamp_val,
                   sensor_status, device_hash, signature, counter)
                VALUES (1, :1, :2, TO_DATE(:3,'YYYY-MM-DD\"T\"HH24:MI:SS'), :4, :5, :6, :7)
                RETURNING measurement_id INTO :8
                """,
                (m.device_id, temp, m.timestamp, m.sensor_status,
                 m.device_hash, m.signature, m.counter, measurement_id_var),
            )
        except oracledb.DatabaseError as e:
            if "ORA-00001" in str(e) or "ORA-20001" in str(e):
                raise HTTPException(409, "Replay detected")
            raise HTTPException(400, "Rejected by database constraint")
        measurement_id = measurement_id_var.getvalue()[0]

        try:
            tx_hash = chain.store(measurement_id, m.device_id, m.device_hash, m.counter)
        except Exception as e:
            raise HTTPException(502, f"Blockchain write failed: {e}")
        cur.execute(
            "INSERT INTO BLOCKCHAIN_RECORD (measurement_id, data_hash, transaction_hash) VALUES (:1, :2, :3)",
            (measurement_id, m.device_hash, tx_hash),
        )

        if m.sensor_status in ALERTS:
            cur.execute(
                "INSERT INTO ALERT (measurement_id, alert_type, severity) VALUES (:1, :2, :3)",
                (measurement_id, m.sensor_status, ALERTS[m.sensor_status]),
            )

        db.commit()

    return {"status": "ACCEPTED", "measurement_id": measurement_id, "device_hash": m.device_hash}


@app.get("/verify/{measurement_id}")
def verify(measurement_id: int):
    """Recompute everything from stored data. Trust nothing stored."""
    with db_conn() as db:
        cur = db.cursor()
        cur.execute(
            """
            SELECT m.device_id, m.temperature,
                   TO_CHAR(m.timestamp_val,'YYYY-MM-DD"T"HH24:MI:SS') AS ts,
                   m.sensor_status, m.counter, m.device_hash, m.signature,
                     b.transaction_hash, d.public_key
            FROM MEASUREMENT m
                 LEFT JOIN BLOCKCHAIN_RECORD b ON b.measurement_id = m.measurement_id
            JOIN DEVICE d ON d.device_id = m.device_id
            WHERE m.measurement_id = :1
            """,
            (measurement_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Not found")
        (dev, temp, ts, status, counter, db_hash, sig, tx_hash, pubkey) = row

    if counter is None or sig is None or not pubkey:
        return {"status": "TAMPERED", "reason": "missing signature/counter/public key"}

    rec = chain.get(measurement_id)
    chain_hash = rec["hash"] if rec else None
    key_anchored = chain.device_key_hash(dev) == hashlib.sha256(pubkey.encode()).digest()

    payload = build_payload(dev, temp, ts, status, counter)
    recomputed = sha256_hex(payload)

    checks = {
        "recomputed_matches_db_hash": recomputed == db_hash,
        "signature_valid": verify_signature(pubkey, payload, sig),
        "recomputed_matches_chain_hash": recomputed == chain_hash,
        "public_key_matches_chain": key_anchored,
    }
    return {
        "status": "VERIFIED" if all(checks.values()) else "TAMPERED",
        "measurement_id": measurement_id,
        "checks": checks,
        "recomputed_hash": recomputed,
        "db_hash": db_hash,
        "chain_hash": chain_hash,
        "transaction_hash": tx_hash,
    }


@app.get("/measurements")
def list_all():
    with db_conn() as db:
        cur = db.cursor()
        cur.execute(
            """SELECT * FROM MEASUREMENT
               ORDER BY measurement_id DESC
               FETCH FIRST 20 ROWS ONLY"""
        )
        return [cursor_to_dict(cur, r) for r in cur.fetchall()]
