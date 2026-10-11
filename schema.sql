-- Run as mediledger:
--   sqlplus mediledger/mediled123@localhost:1521/freepdb1 @schema.sql
-- Fresh DB: includes signature/counter/public_key already. No migration needed.

CREATE TABLE PATIENT (
    patient_id  NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        VARCHAR2(100) NOT NULL,
    created_at  TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE TABLE DEVICE (
    device_id    VARCHAR2(50) PRIMARY KEY,
    public_key   VARCHAR2(400),                 -- ECDSA P-256 PEM (public only)
    status       VARCHAR2(10) DEFAULT 'ACTIVE' NOT NULL,
    registered_at TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE TABLE MEASUREMENT (
    measurement_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    patient_id     NUMBER NOT NULL REFERENCES PATIENT(patient_id),
    device_id      VARCHAR2(50) NOT NULL REFERENCES DEVICE(device_id),
    temperature    NUMBER(5,2) NOT NULL,
    timestamp_val  DATE NOT NULL,
    sensor_status  VARCHAR2(20) NOT NULL,
    device_hash    VARCHAR2(64) NOT NULL,       -- sha256 hex
    signature      VARCHAR2(200) NOT NULL,      -- base64 DER ECDSA
    counter        NUMBER NOT NULL,
    created_at     TIMESTAMP DEFAULT SYSTIMESTAMP,
    CONSTRAINT uq_device_counter UNIQUE (device_id, counter)  -- DB-level replay block
);

CREATE TABLE BLOCKCHAIN_RECORD (
    record_id        NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    measurement_id   NUMBER NOT NULL REFERENCES MEASUREMENT(measurement_id),
    data_hash        VARCHAR2(64) NOT NULL,
    transaction_hash VARCHAR2(100),
    created_at       TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE TABLE ALERT (
    alert_id       NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    measurement_id NUMBER NOT NULL REFERENCES MEASUREMENT(measurement_id),
    alert_type     VARCHAR2(50) NOT NULL,
    severity       VARCHAR2(10) NOT NULL,
    created_at     TIMESTAMP DEFAULT SYSTIMESTAMP
);

-- Seed: patient 1 (code hardcodes patient_id=1) + device row.
-- public_key filled later by: python register_device.py ESP32_001
INSERT INTO PATIENT (name) VALUES ('Demo Patient');
INSERT INTO DEVICE (device_id, status) VALUES ('ESP32_001', 'ACTIVE');
COMMIT;

SELECT table_name FROM user_tables;
