import requests

B = "http://localhost:8000"
SHORT = {
    "recomputed_matches_db_hash": "db_hash",
    "signature_valid": "signature",
    "recomputed_matches_chain_hash": "chain_hash",
    "public_key_matches_chain": "key_anchor",
}

rows = requests.get(f"{B}/measurements", timeout=10).json()
print(f"{'ID':>4} {'TEMP':>6} {'STATUS':<13} {'RESULT'}")
print("-" * 50)
for r in sorted(rows, key=lambda x: x["measurement_id"]):
    v = requests.get(f"{B}/verify/{r['measurement_id']}", timeout=10).json()
    failed = [SHORT.get(k, k) for k, ok in v.get("checks", {}).items() if not ok]
    if v.get("status") == "VERIFIED":
        res = "✔ VERIFIED"
    else:
        res = "✘ TAMPERED " + ("(" + ", ".join(failed) + ")" if failed else v.get("reason", ""))
    print(f"{r['measurement_id']:>4} {float(r['temperature']):>6.2f} {r['sensor_status']:<13} {res}")