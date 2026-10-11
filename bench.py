"""bench.py: numbers for report section 6.4.
Run in project root with backend + hardhat node running.
Use the OWNER account: do NOT set DB_USER / DB_PASS in this terminal."""
import statistics as st, sys, time
import requests
from fake_device import make_packet, URL
from main import get_db
import chain

BASE = URL.rsplit("/", 1)[0]
N, ROWS, CHAIN_N = 200, 200_000, 50

def stats(v):
    v = sorted(v)
    return st.mean(v) * 1000, st.median(v) * 1000, v[max(0, int(len(v) * 0.95) - 1)] * 1000

try:
    requests.get(BASE + "/", timeout=5)
except Exception as e:
    sys.exit(f"Backend not reachable at {BASE}: {e}")

# 1. ingest
s = requests.Session()
base = int(time.time() * 1000)
ids, ing = [], []
t0 = time.perf_counter()
for i in range(N):
    p = make_packet(36.8 + (i % 5) * 0.1, counter=base + i)
    t = time.perf_counter()
    r = s.post(URL, json=p, timeout=10)
    ing.append(time.perf_counter() - t)
    if r.status_code != 200:
        sys.exit(f"Ingest failed at packet {i}: {r.status_code} {r.text}")
    ids.append(r.json()["measurement_id"])
total = time.perf_counter() - t0
ing_m, ing_med, ing_p95 = stats(ing)

# 2. ledger write time on its own
cid = int(time.time()) * 1000
ch = []
for i in range(CHAIN_N):
    t = time.perf_counter()
    chain.store(cid + i, "BENCH", "00" * 32, i + 1)
    ch.append(time.perf_counter() - t)
ch_m = stats(ch)[0]

# 3. verify + false positives
ver, bad = [], 0
for i in ids:
    t = time.perf_counter()
    v = s.get(f"{BASE}/verify/{i}", timeout=10).json()
    ver.append(time.perf_counter() - t)
    if v.get("status") != "VERIFIED":
        bad += 1
ver_m, ver_med, ver_p95 = stats(ver)

# 4. replay lookup, with and without index (scratch table)
db = get_db(); cur = db.cursor()
def plan_op():
    cur.execute("EXPLAIN PLAN FOR SELECT NVL(MAX(counter),0) FROM BENCH_M WHERE device_id='DEV1'")
    cur.execute("SELECT plan_table_output FROM TABLE(DBMS_XPLAN.DISPLAY)")
    for (line,) in cur.fetchall():
        if "TABLE ACCESS" in line or "INDEX" in line:
            return line.split("|")[2].strip()
    return "?"
def lookup():
    ts = []
    for i in range(50):
        t = time.perf_counter()
        cur.execute("SELECT NVL(MAX(counter),0) FROM BENCH_M WHERE device_id=:1", (f"DEV{i}",))
        cur.fetchone()
        ts.append(time.perf_counter() - t)
    return st.mean(ts) * 1000
try:
    try: cur.execute("DROP TABLE BENCH_M PURGE")
    except Exception: pass
    cur.execute("CREATE TABLE BENCH_M (device_id VARCHAR2(50) NOT NULL, counter NUMBER NOT NULL)")
    cur.execute("INSERT INTO BENCH_M SELECT 'DEV'||MOD(LEVEL,50), LEVEL FROM DUAL CONNECT BY LEVEL <= :1", (ROWS,))
    db.commit()
    cur.execute("BEGIN DBMS_STATS.GATHER_TABLE_STATS(USER,'BENCH_M'); END;")
    no_idx, op1 = lookup(), plan_op()
    cur.execute("CREATE UNIQUE INDEX bench_ix ON BENCH_M (device_id, counter)")
    cur.execute("BEGIN DBMS_STATS.GATHER_TABLE_STATS(USER,'BENCH_M'); END;")
    idx, op2 = lookup(), plan_op()
finally:
    try: cur.execute("DROP TABLE BENCH_M PURGE")
    except Exception: pass
    db.close()

rows = [
    ("Ingest latency, mean / median / p95 (ms)", f"{ing_m:.1f} / {ing_med:.1f} / {ing_p95:.1f}"),
    ("Chain write only, mean (ms)", f"{ch_m:.1f}"),
    ("Ingest without ledger, estimated (ms)", f"{max(ing_m - ch_m, 0):.1f}"),
    ("Verify latency, mean / median / p95 (ms)", f"{ver_m:.1f} / {ver_med:.1f} / {ver_p95:.1f}"),
    ("Throughput (readings/sec)", f"{N / total:.1f}"),
    ("False positives", f"{bad} of {N}"),
    (f"Replay lookup, no index, {ROWS:,} rows (ms)", f"{no_idx:.2f}  [{op1}]"),
    (f"Replay lookup, with index (ms)", f"{idx:.2f}  [{op2}]"),
    ("Index speedup", f"{no_idx / idx:.1f}x" if idx else "n/a"),
]
w = max(len(a) for a, _ in rows)
print()
for a, b in rows: print(f"{a:<{w}}  {b}")
with open("bench_results.md", "w", encoding="utf-8") as f:
    f.write("| Metric | Result |\n|---|---|\n")
    for a, b in rows: f.write(f"| {a} | {b} |\n")
print("\nSaved bench_results.md")