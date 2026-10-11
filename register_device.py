"""Run once. Makes keypair. Private key -> device_private.pem (stays 'on device').
Public key -> DEVICE.public_key in DB. Backend never sees private key."""
import os, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from main import get_db

DEVICE_ID = sys.argv[1] if len(sys.argv) > 1 else "ESP32_001"
KEY_FILE = "device_private.pem"

if os.path.exists(KEY_FILE):
    priv = serialization.load_pem_private_key(open(KEY_FILE, "rb").read(), None)
    print("Using existing", KEY_FILE)
else:
    priv = ec.generate_private_key(ec.SECP256R1())
    open(KEY_FILE, "wb").write(priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    print("Wrote", KEY_FILE)

pub_pem = priv.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo).decode()

db = get_db()
cur = db.cursor()
cur.execute("UPDATE DEVICE SET public_key=:1 WHERE device_id=:2", (pub_pem, DEVICE_ID))
print("rows updated:", cur.rowcount, "(0 = device row missing, insert it first)")
db.commit()
import hashlib, chain
new_fp = hashlib.sha256(pub_pem.encode()).digest()
old_fp = chain.device_key_hash(DEVICE_ID)
if old_fp == b"\x00" * 32:
    print("on-chain tx:", chain.register_device(DEVICE_ID, new_fp))
elif old_fp == new_fp:
    print("Key already anchored on-chain, same key. OK.")
else:
    print("WARNING: a DIFFERENT key is already anchored on-chain. NOT overwriting.")
db.close()
