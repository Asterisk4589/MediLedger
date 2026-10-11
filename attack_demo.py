"""Demo attacks. Each must FAIL. Run after fake_device.py."""
import base64, copy, requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fake_device import make_packet, build_payload, DEVICE_ID, URL
import hashlib

def show(name, r): print(f"{name:32} → {r.status_code} {r.json()}")

# 1. replay: resend old packet
p = make_packet(36.5)
show("legit packet", requests.post(URL, json=p))
show("replay same packet", requests.post(URL, json=p))

# 2. tamper data in transit (hash + sig no longer match)
t = copy.deepcopy(make_packet(36.5)); t["temperature"] = 30.0
show("tamper temperature in transit", requests.post(URL, json=t))

# 3. attacker/backend forges: recompute hash, sign with OWN key
evil = ec.generate_private_key(ec.SECP256R1())
f = make_packet(36.5); f["temperature"] = 30.0
payload = build_payload(DEVICE_ID, 30.0, f["timestamp"], f["sensor_status"], f["counter"])
f["device_hash"] = hashlib.sha256(payload).hexdigest()
f["signature"] = base64.b64encode(evil.sign(payload, ec.ECDSA(hashes.SHA256()))).decode()
show("forge hash + wrong key", requests.post(URL, json=f))
