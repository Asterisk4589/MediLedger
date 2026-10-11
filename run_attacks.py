import csv
import hashlib
import os
import sys
import time
import textwrap
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
BASE_URL = "http://localhost:8000"
CSV_PATH = ROOT / "attack_results.csv"
MATRIX_PATH = ROOT / "attack_matrix.md"
FIELDS = ["#", "Attack", "Layer", "Expected", "Actual", "Failed checks", "Result"]

try:
    root_response = requests.get(BASE_URL + "/", timeout=10)
    if root_response.status_code != 200:
        print(f"ERROR: backend health check returned HTTP {root_response.status_code}; expected HTTP 200")
        sys.exit(1)
except requests.RequestException as exc:
    print(f"ERROR: backend health check failed: {exc}")
    sys.exit(1)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fake_device import DEVICE_ID, build_payload, make_packet
from main import get_db

last_counter = 0
victim_ids = []
restore_errors = []


def fresh_packet(temperature=36.8):
    global last_counter
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute("SELECT NVL(MAX(counter), 0) FROM MEASUREMENT WHERE device_id=:1", (DEVICE_ID,))
        db_counter = int(cur.fetchone()[0])
    finally:
        db.close()
    last_counter = max(db_counter, last_counter, int(time.time() * 1000) - 1) + 1
    return make_packet(temperature, counter=last_counter)


def post_status(packet):
    try:
        return requests.post(BASE_URL + "/measurement", json=packet, timeout=10).status_code
    except requests.RequestException as exc:
        return f"ERROR: {exc}"


def post_fresh_measurement():
    response = requests.post(BASE_URL + "/measurement", json=fresh_packet(), timeout=10)
    if response.status_code != 200:
        raise RuntimeError(f"measurement POST returned HTTP {response.status_code}")
    measurement_id = response.json().get("measurement_id")
    if measurement_id is None:
        raise RuntimeError("measurement response did not include measurement_id")
    return int(measurement_id)


def verify_measurement(measurement_id):
    response = requests.get(f"{BASE_URL}/verify/{measurement_id}", timeout=10)
    response.raise_for_status()
    return response.json()


def failed_checks(result):
    return [name for name, passed in result.get("checks", {}).items() if not passed]


def make_row(number, attack, layer, expected, actual, failed, passed):
    return {
        "#": number,
        "Attack": attack,
        "Layer": layer,
        "Expected": expected,
        "Actual": actual,
        "Failed checks": ", ".join(failed) if failed else "-",
        "Result": "PASS" if passed else "FAIL",
    }


def run_network_attacks(attacker_key):
    rows = []

    packet = fresh_packet()
    first_status = post_status(packet)
    second_status = post_status(packet)
    actual = f"{first_status} then {second_status}"
    rows.append(make_row("N1", "Replay", "Network", "200 then 409", actual, [],
                         (first_status, second_status) == (200, 409)))

    packet = fresh_packet()
    packet["temperature"] = 30.0
    status = post_status(packet)
    rows.append(make_row("N2", "Tamper in transit", "Network", "400", str(status), [], status == 400))

    packet = fresh_packet()
    temperature = 30.0
    payload = build_payload(
        packet["device_id"], temperature, packet["timestamp"], packet["sensor_status"], packet["counter"]
    )
    packet["temperature"] = temperature
    packet["device_hash"] = hashlib.sha256(payload).hexdigest()
    packet["signature"] = __import__("base64").b64encode(
        attacker_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    ).decode()
    status = post_status(packet)
    rows.append(make_row("N3", "Forge hash + attacker's key", "Network", "401", str(status), [], status == 401))
    return rows


def snapshot_measurement(measurement_id):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute(
            """SELECT m.device_id, m.temperature, m.timestamp_val, m.sensor_status,
                      m.device_hash, m.signature, m.counter, d.public_key
               FROM MEASUREMENT m JOIN DEVICE d ON d.device_id=m.device_id
               WHERE m.measurement_id=:1""",
            (measurement_id,),
        )
        row = cur.fetchone()
        if not row:
            raise RuntimeError(f"measurement {measurement_id} was not found")
        cur.execute("SELECT data_hash FROM BLOCKCHAIN_RECORD WHERE measurement_id=:1", (measurement_id,))
        block_row = cur.fetchone()
        if not block_row:
            raise RuntimeError(f"blockchain record for measurement {measurement_id} was not found")
        return {
            "device_id": row[0],
            "temperature": row[1],
            "timestamp_val": row[2],
            "sensor_status": row[3],
            "device_hash": row[4],
            "signature": row[5],
            "counter": row[6],
            "public_key": row[7],
            "block_data_hash": block_row[0],
        }
    finally:
        db.close()


def restore_measurement(measurement_id, original):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute(
            "UPDATE MEASUREMENT SET temperature=:1, device_hash=:2, signature=:3 WHERE measurement_id=:4",
            (original["temperature"], original["device_hash"], original["signature"], measurement_id),
        )
        cur.execute(
            "UPDATE BLOCKCHAIN_RECORD SET data_hash=:1 WHERE measurement_id=:2",
            (original["block_data_hash"], measurement_id),
        )
        cur.execute(
            "UPDATE DEVICE SET public_key=:1 WHERE device_id=:2",
            (original["public_key"], original["device_id"]),
        )
        db.commit()
    finally:
        db.close()


def changed_payload(original, temperature):
    timestamp = original["timestamp_val"].strftime("%Y-%m-%dT%H:%M:%S")
    payload = build_payload(
        original["device_id"], temperature, timestamp,
        original["sensor_status"], original["counter"],
    )
    return payload, hashlib.sha256(payload).hexdigest()


def apply_database_attack(number, original, measurement_id, attacker_key, attacker_public_pem):
    db = get_db()
    try:
        cur = db.cursor()
        temperature = round(float(original["temperature"]) + 10.0, 2)
        if number == "D1":
            cur.execute("UPDATE MEASUREMENT SET temperature=:1 WHERE measurement_id=:2", (temperature, measurement_id))
        elif number == "D2":
            _, new_hash = changed_payload(original, temperature)
            cur.execute(
                "UPDATE MEASUREMENT SET temperature=:1, device_hash=:2 WHERE measurement_id=:3",
                (temperature, new_hash, measurement_id),
            )
            cur.execute(
                "UPDATE BLOCKCHAIN_RECORD SET data_hash=:1 WHERE measurement_id=:2",
                (new_hash, measurement_id),
            )
        else:
            payload, new_hash = changed_payload(original, temperature)
            signature = __import__("base64").b64encode(
                attacker_key.sign(payload, ec.ECDSA(hashes.SHA256()))
            ).decode()
            cur.execute(
                "UPDATE MEASUREMENT SET temperature=:1, device_hash=:2, signature=:3 WHERE measurement_id=:4",
                (temperature, new_hash, signature, measurement_id),
            )
            cur.execute(
                "UPDATE DEVICE SET public_key=:1 WHERE device_id=:2",
                (attacker_public_pem, original["device_id"]),
            )
        db.commit()
    finally:
        db.close()


EXPECTED_DB_FAILURES = {
    "D1": ["recomputed_matches_db_hash", "signature_valid", "recomputed_matches_chain_hash"],
    "D2": ["signature_valid", "recomputed_matches_chain_hash"],
    "D3": ["recomputed_matches_chain_hash", "public_key_matches_chain"],
}


def run_database_attack(number, attack, attacker_key, attacker_public_pem):
    expected_failed = EXPECTED_DB_FAILURES[number]
    expected = "TAMPERED; fails " + ", ".join(expected_failed)
    measurement_id = None
    original = None
    actual = "ERROR"
    failed = []
    passed = False
    try:
        measurement_id = post_fresh_measurement()
        victim_ids.append(measurement_id)
        original = snapshot_measurement(measurement_id)
        apply_database_attack(number, original, measurement_id, attacker_key, attacker_public_pem)
        result = verify_measurement(measurement_id)
        actual = result.get("status", "missing status")
        failed = failed_checks(result)
        passed = actual == "TAMPERED" and set(failed) == set(expected_failed)
    except Exception as exc:
        actual = f"ERROR: {exc}"
    finally:
        if measurement_id is not None and original is not None:
            try:
                restore_measurement(measurement_id, original)
            except Exception as exc:
                restore_errors.append(f"{measurement_id}: {exc}")
    return make_row(number, attack, "Database", expected, actual, failed, passed)


def run_control():
    try:
        measurement_id = post_fresh_measurement()
        result = verify_measurement(measurement_id)
        actual = result.get("status", "missing status")
        failed = failed_checks(result)
        passed = actual == "VERIFIED" and bool(result.get("checks")) and not failed
    except Exception as exc:
        actual = f"ERROR: {exc}"
        failed = []
        passed = False
    return make_row("C1", "Untouched measurement", "Control", "VERIFIED; all checks true", actual, failed, passed)


def write_results(rows):
    with CSV_PATH.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# Attack Matrix",
        "",
        "| " + " | ".join(FIELDS) + " |",
        "| " + " | ".join(["---"] * len(FIELDS)) + " |",
    ]
    for row in rows:
        values = [str(row[field]).replace("|", "\\|").replace("\n", " ") for field in FIELDS]
        lines.append("| " + " | ".join(values) + " |")
    lines.extend([
        "",
        "## Limits (not tested)",
        "",
        "- Compromised device signing false readings",
        "- Dropped packets",
        "- DoS",
        "- Simulated device instead of real ESP32",
        "",
    ])
    MATRIX_PATH.write_text("\n".join(lines), encoding="utf-8")


def print_table(rows):
    widths = [4, 29, 9, 48, 23, 52, 6]

    def print_cells(values):
        wrapped = [
            textwrap.wrap(str(value), width=width, break_long_words=False) or [""]
            for value, width in zip(values, widths)
        ]
        for line in range(max(len(cell) for cell in wrapped)):
            cells = [
                (cell[line] if line < len(cell) else "").ljust(width)
                for cell, width in zip(wrapped, widths)
            ]
            print(" | ".join(cells))

    print_cells(FIELDS)
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print_cells([str(row[field]).replace("\n", " ") for field in FIELDS])


def check_restored_state():
    problems = list(restore_errors)
    for measurement_id in victim_ids:
        try:
            result = verify_measurement(measurement_id)
            if result.get("status") != "VERIFIED" or not result.get("checks") or not all(result["checks"].values()):
                problems.append(f"{measurement_id}: verify returned {result.get('status', 'no status')}")
        except Exception as exc:
            problems.append(f"{measurement_id}: {exc}")
    if problems:
        print("STATE RESTORATION PROBLEM: " + "; ".join(problems))
        return False
    print("STATE RESTORED")
    return True


def main():
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    attacker_public_pem = attacker_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    rows = run_network_attacks(attacker_key)
    rows.append(run_database_attack("D1", "Edit temperature only", attacker_key, attacker_public_pem))
    rows.append(run_database_attack("D2", "Edit temperature + rewrite hashes", attacker_key, attacker_public_pem))
    rows.append(run_database_attack("D3", "Swap public key + re-sign", attacker_key, attacker_public_pem))
    rows.append(run_control())
    print_table(rows)
    write_results(rows)
    restored = check_restored_state()
    print(f"Wrote {MATRIX_PATH.name} and {CSV_PATH.name}")
    if not restored or any(row["Result"] != "PASS" for row in rows):
        sys.exit(1)


if __name__ == "__main__":
    main()