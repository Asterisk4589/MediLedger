# MediLedger 🏥⛓️

> Hardware-Authenticated IoT Health Data Integrity Using Blockchain

## What is MediLedger?

MediLedger is a tamper-evident health data monitoring system where physiological measurements are **cryptographically signed at the hardware edge** before transmission — making it impossible for any downstream system (backend, database, or network) to forge or alter a measurement without detection.

Unlike generic blockchain health projects that simply store data on-chain, MediLedger focuses on **verifiable measurement provenance**: proving that a reading originated from a registered physical device AND was never modified after recording.

---

## How It Works

```
ESP32 Sensor → HMAC signed on-device → FastAPI Backend → Oracle DB → Blockchain Hash
                                                                            ↓
                                                                    Tamper Verification
```

1. **Hardware Layer** — ESP32 + DS18B20 reads temperature
2. **Edge Signing** — HMAC-SHA256 generated ON the device before sending
3. **Backend** — Validates device identity + verifies signature
4. **Database** — Stores measurement with hash (Oracle DB)
5. **Blockchain** — Anchors hash as immutable proof
6. **Verification** — Any DB tampering = hash mismatch = detected

---

## Key Features

- ✅ **Device Authentication** — Only registered devices can submit data
- ✅ **Edge-Originated Integrity** — Hash generated on hardware, not backend
- ✅ **Tamper Detection** — Any post-submission DB change is immediately detectable
- ✅ **Sensor Anomaly Detection** — Device flags readings outside physiological range
- ✅ **Privacy Preserving** — Patient data stays in DB, only hashes go on blockchain
- ✅ **Dual Verification** — Device authenticity + data integrity as separate guarantees

---

## Tech Stack

| Layer | Technology |
|---|---|
| Hardware | ESP32 + DS18B20 (Wokwi simulation) |
| Firmware | Arduino C++ (HMAC-SHA256 via mbedtls) |
| Backend | Python + FastAPI |
| Database | Oracle XE (freepdb1) |
| Blockchain | Ganache + Web3.py + Solidity |
| Dashboard | HTML + JavaScript |

---

## Project Structure

```
MediLedger/
├── main.py              # FastAPI backend
├── chain.py             # Blockchain integration
├── fake_device.py       # ESP32 simulator for testing
├── dashboard.html       # Verification dashboard
├── schema.sql           # Oracle DB schema
├── register_device.py   # Device registration
├── run_attacks.py       # Tamper detection demo
├── show.py              # Display utilities
├── bench.py             # Performance benchmarks
├── blockchain/          # Smart contracts
└── requirements.txt     # Dependencies
```

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Oracle DB setup
```bash
sqlplus mediledger/mediled123@localhost:1521/freepdb1
# Run schema.sql
```

### 3. Start backend
```bash
python -m uvicorn main:app --reload --port 8000
```

### 4. Simulate device
```bash
python fake_device.py
```

### 5. Open dashboard
Open `dashboard.html` in browser → `http://localhost:8000`

---

## The Killer Demo

1. Send measurement via `fake_device.py`
2. Open `/verify/1` → see ✅ VERIFIED
3. Manually change temperature in DB
4. Refresh → see ⚠️ TAMPERED + hash mismatch

---

## SDG Alignment

- **SDG 3** — Good Health and Well-being (primary)
- **SDG 9** — Industry, Innovation and Infrastructure

---

## Team

**Out Of Tokens** — VIT Chennai, Blockchain Minor Project 2026

---

## TRL Status

**TRL 3** — Experimental Proof of Concept
