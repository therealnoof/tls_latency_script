# TLS Key Exchange Latency Lab Guide

## Lab Overview

This lab measures the latency impact of Post-Quantum Cryptography (PQC) on TLS handshakes by comparing classical ECDH key exchanges against PQC hybrid ciphers. Traffic flows through an F5 BIG-IP, which terminates TLS and forwards requests to a simple backend application.

## Architecture

```
┌──────────────┐         ┌─────────────────────────────────┐         ┌──────────────┐
│              │         │           F5 BIG-IP             │         │              │
│              │         │                                 │         │              │
│  Test Server │────────►│  VIP 10.1.10.20 (No PQC)       │────────►│  App Server  │
│              │         │    - TLS 1.2 + 1.3 ECDH only   │         │              │
│  Ubuntu 22   │         │    - Standard clientssl profile │         │  nginx       │
│  10.1.1.5    │         │                                 │         │  (Docker)    │
│              │────────►│  VIP 10.1.10.30 (PQC)           │────────►│              │
│              │         │    - TLS 1.3 PQC hybrid ciphers │         │              │
│              │         │    - PQC-enabled clientssl       │         │              │
└──────────────┘         └─────────────────────────────────┘         └──────────────┘
```

### Components

- **Test Server** — Ubuntu 22.04 machine with curl 8.12.1 built against OpenSSL 3.5.0 for PQC support. Runs the benchmark script.
- **F5 BIG-IP** — Two virtual servers (VIPs) on the same BIG-IP, each with a different clientssl profile:
  - **10.1.10.20** — Standard profile (ECDH only, no PQC ciphers)
  - **10.1.10.30** — PQC-enabled profile (ECDH + ML-KEM/Kyber hybrid key exchanges)
- **App Server** — A lightweight nginx container (Docker) serving as the backend pool member. Returns a simple JSON response.

### What the Script Measures

The benchmark script (`tls_latency_bench.py`) isolates **TLS handshake latency** — the time between the TCP connection being established and the TLS negotiation completing. It excludes DNS lookup, TCP connect, and HTTP request/response times.

For each VIP, the script tests up to 8 key exchange configurations:

| Test Case | TLS Version | What It Measures |
|---|---|---|
| ECDHE-P256 | 1.2 | Baseline — most common TLS 1.2 key exchange |
| ECDHE-P384 | 1.2 | Larger curve, slower than P-256 |
| X25519 | 1.3 | Fast modern curve, TLS 1.3 default |
| P-256 | 1.3 | NIST curve over TLS 1.3 |
| P-384 | 1.3 | Larger NIST curve over TLS 1.3 |
| X25519+MLKEM768 hybrid | 1.3 | **PQC hybrid** — classical + post-quantum combined |
| SecP256r1+MLKEM768 hybrid | 1.3 | **PQC hybrid** — P-256 + ML-KEM |
| X25519+Kyber768 draft hybrid | 1.3 | **PQC hybrid** — draft Kyber standard |

The non-PQC VIP (10.1.10.20) will succeed on the ECDH tests and skip the PQC tests. The PQC VIP (10.1.10.30) should succeed on both ECDH and PQC tests, allowing a direct comparison.

---

## Running the Lab

### 1. Log into the test server

```bash
ssh ubuntu@10.1.1.5
```

### 2. Navigate to the test directory

```bash
cd /home/ubuntu/tls_latency_script
```

### 3. Run the benchmark against both VIPs

```bash
python3 tls_latency_bench.py -t 10.1.10.20 10.1.10.30 -k -n 30
```

**Flags:**
- `-t 10.1.10.20 10.1.10.30` — target both VIPs
- `-k` — skip certificate verification (required since the BIG-IP uses a self-signed cert)
- `-n 30` — run 30 measured iterations per test case (default)

For a quicker smoke test:

```bash
python3 tls_latency_bench.py -t 10.1.10.20 10.1.10.30 -k -n 10
```

For higher-fidelity results:

```bash
python3 tls_latency_bench.py -t 10.1.10.20 10.1.10.30 -k -n 100 --warmup 5
```

### 4. Export results to CSV (optional)

```bash
python3 tls_latency_bench.py -t 10.1.10.20 10.1.10.30 -k -n 50 --csv results.csv
```

---

## Understanding the Output

The script prints a results table for each VIP:

```
============================================================================================
  Target: 10.1.10.20
============================================================================================
Key Exchange                                 Min     Avg     Med     P95     Max      σ        Δ
--------------------------------------------------------------------------------------------
ECDHE-P256 (TLS 1.2)                       2.31    3.12    2.95    4.10    5.22   0.68   (base)
ECDHE-P384 (TLS 1.2)                       2.88    3.75    3.50    4.95    6.11   0.81  (+20.2%)
X25519 (TLS 1.3)                           1.95    2.60    2.45    3.30    4.15   0.55  (-16.7%)
P-256 (TLS 1.3)                            2.20    3.05    2.90    4.00    5.10   0.65   (-2.2%)
P-384 (TLS 1.3)                            2.75    3.65    3.40    4.80    5.90   0.78  (+17.0%)
X25519+MLKEM768 hybrid (TLS 1.3)                              — unsupported / unreachable —
SecP256r1+MLKEM768 hybrid (TLS 1.3)                            — unsupported / unreachable —
X25519+Kyber768 draft hybrid (TLS 1.3)                         — unsupported / unreachable —
============================================================================================

============================================================================================
  Target: 10.1.10.30
============================================================================================
Key Exchange                                 Min     Avg     Med     P95     Max      σ        Δ
--------------------------------------------------------------------------------------------
ECDHE-P256 (TLS 1.2)                       2.35    3.18    3.00    4.15    5.30   0.70   (base)
ECDHE-P384 (TLS 1.2)                       2.90    3.80    3.55    5.00    6.20   0.83  (+19.5%)
X25519 (TLS 1.3)                           1.98    2.65    2.50    3.35    4.20   0.57  (-16.7%)
P-256 (TLS 1.3)                            2.25    3.10    2.95    4.05    5.15   0.67   (-2.5%)
P-384 (TLS 1.3)                            2.80    3.70    3.45    4.85    5.95   0.80  (+16.4%)
X25519+MLKEM768 hybrid (TLS 1.3)           2.10    2.85    2.70    3.60    4.50   0.62  (-10.4%)
SecP256r1+MLKEM768 hybrid (TLS 1.3)        2.30    3.20    3.05    4.20    5.35   0.70   (+0.6%)
X25519+Kyber768 draft hybrid (TLS 1.3)     2.15    2.90    2.75    3.65    4.55   0.63   (-8.8%)
============================================================================================
```

### Column definitions

| Column | Meaning |
|---|---|
| **Min** | Fastest handshake observed (ms) |
| **Avg** | Mean handshake time across all iterations (ms) |
| **Med** | Median handshake time (ms) — less sensitive to outliers than avg |
| **P95** | 95th percentile — 95% of handshakes were faster than this (ms) |
| **Max** | Slowest handshake observed (ms) |
| **σ** | Standard deviation — measures consistency (lower = more stable) |
| **Δ** | Percentage difference in avg compared to the first successful test (base) |

### What to look for

- **ECDH baseline** — X25519 on TLS 1.3 is typically the fastest. P-384 is the slowest due to larger key size.
- **PQC overhead** — Compare the PQC hybrid results on 10.1.10.30 against the ECDH baselines. The hybrid handshakes include both a classical key exchange and a post-quantum key exchange, so some overhead is expected.
- **"unsupported / unreachable"** — Means the VIP's clientssl profile does not support that key exchange. Expected on 10.1.10.20 (non-PQC) for all PQC tests.
- **σ (stddev)** — High values indicate inconsistent latency. If stddev is large relative to the average, consider running more iterations (`-n 100`) or checking for network congestion.

---

## Troubleshooting

### Backend application is down

If all tests show "unsupported / unreachable" on both VIPs, or if the F5 pool members are showing as down, the backend application may not be running.

#### Check the backend status

SSH into the app server and check:

```bash
cd /home/ubuntu/tls_latency_script/backend
docker compose ps
```

#### Start the backend

```bash
cd /home/ubuntu/tls_latency_script/backend
docker compose up -d --build
```

#### Verify it's healthy

```bash
# HTTP health check
curl http://localhost/health
# Expected: {"status":"ok"}

# HTTPS check (self-signed cert)
curl -k https://localhost/
# Expected: {"service":"tls-latency-backend","proto":"https"}
```

#### Restart if it's misbehaving

```bash
cd /home/ubuntu/tls_latency_script/backend
docker compose down
docker compose up -d --build
```

#### View logs

```bash
cd /home/ubuntu/tls_latency_script/backend
docker compose logs -f
```

### Script shows all tests as SKIPPED

1. **Verify network connectivity** — Can you reach the VIPs from the test server?
   ```bash
   curl -kvso /dev/null https://10.1.10.20/ 2>&1 | head -20
   curl -kvso /dev/null https://10.1.10.30/ 2>&1 | head -20
   ```

2. **Check curl version** — PQC tests require curl 8.x with OpenSSL 3.2+:
   ```bash
   which curl
   curl --version
   ```
   If it shows the old system curl (7.x), set the path:
   ```bash
   export PATH=/usr/local/bin:$PATH
   export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/openssl-3.5/lib64:$LD_LIBRARY_PATH
   ```

3. **Check F5 VIP status** — Ensure both virtual servers are available and pool members are healthy:
   ```bash
   # From the BIG-IP CLI
   tmsh show ltm virtual
   tmsh show ltm pool
   ```
