"""Simulates ESP32: reads sensor, hashes + signs ON DEVICE, sends data+hash+signature."""
import base64, hashlib, time
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

DEVICE_ID = "ESP32_001"
URL = "http://localhost:8000/measurement"

priv = serialization.load_pem_private_key(open("device_private.pem", "rb").read(), None)


def build_payload(device_id, temperature, ts, status, counter) -> bytes:
    return f"{device_id}|{float(temperature):.2f}|{ts}|{status}|{int(counter)}".encode()


def classify(temp):
    if temp < 34 or temp > 42: return "SENSOR_FAULT"
    if temp >= 38:             return "FEVER"
    return "VALID"


def make_packet(temp, counter=None, ts=None):
    ts = ts or time.strftime("%Y-%m-%dT%H:%M:%S")
    counter = counter or int(time.time() * 1000)   # monotonic, no state needed
    status = classify(temp)
    payload = build_payload(DEVICE_ID, temp, ts, status, counter)
    return {
        "device_id": DEVICE_ID,
        "temperature": temp,
        "timestamp": ts,
        "sensor_status": status,
        "counter": counter,
        "device_hash": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(
            priv.sign(payload, ec.ECDSA(hashes.SHA256()))).decode(),
    }


if __name__ == "__main__":
    for temp in [36.8, 37.2, 38.5, 39.0, 15.2, 36.1]:
        r = requests.post(URL, json=make_packet(temp))
        print(f"{temp}°C → {r.status_code} {r.json()}")
        time.sleep(2)
