# TLS Key Exchange Latency Benchmark

Measures TLS handshake latency across classical ECDH (TLS 1.2 & 1.3) and Post-Quantum Cryptography (PQC) hybrid key exchanges. Useful for comparing the overhead of PQC migrations on load balancers, VIPs, and CDN endpoints.

## Requirements

- **Python 3.10+**
- **curl** built with OpenSSL 3.2+ (for PQC cipher support)
  - OpenSSL 3.2-3.4: supports `x25519_kyber768` (draft hybrid)
  - OpenSSL 3.5+: supports `X25519MLKEM768`, `SecP256r1MLKEM768` (standardised ML-KEM)
- Network access to the target server(s)

Check your versions:

```bash
curl --version
openssl version
```

## Test Matrix

| Test Case | TLS Version | Key Exchange Group |
|---|---|---|
| ECDHE-P256 | 1.2 | P-256 |
| ECDHE-P384 | 1.2 | P-384 |
| X25519 | 1.3 | X25519 |
| P-256 | 1.3 | P-256 |
| P-384 | 1.3 | P-384 |
| X25519+MLKEM768 hybrid | 1.3 | X25519MLKEM768 |
| SecP256r1+MLKEM768 hybrid | 1.3 | SecP256r1MLKEM768 |
| X25519+Kyber768 draft hybrid | 1.3 | x25519_kyber768 |

Unsupported ciphers (due to curl/OpenSSL version or server config) are automatically detected and skipped.

## Usage

### Basic (single hostname)

```bash
python3 tls_latency_bench.py
```

Runs all tests against `cloudflare.com` with 30 iterations per test case.

### Multiple VIPs by IP

```bash
python3 tls_latency_bench.py -t 10.0.1.10 10.0.1.11 10.0.1.12 -k
```

Tests each VIP sequentially. `-k` skips certificate verification (required when connecting by raw IP without SNI).

### IP targets with SNI hostname

```bash
python3 tls_latency_bench.py -t 10.0.1.10 10.0.1.11 --sni app.example.com
```

Connects to each IP but sends `app.example.com` as the SNI hostname. This lets the server present the correct certificate and avoids needing `-k`.

### Custom iteration count

```bash
python3 tls_latency_bench.py -t 10.0.1.10 -k -n 100
```

Runs 100 measured iterations per test case (plus 3 warmup iterations).

### Export results to CSV

```bash
python3 tls_latency_bench.py -t 10.0.1.10 10.0.1.11 -k --csv results.csv
```

Writes all results to `results.csv` with columns: `target, label, tls_version, group, min_ms, avg_ms, median_ms, p95_ms, max_ms, stddev_ms, samples, errors`.

### Adjust warmup and timeout

```bash
python3 tls_latency_bench.py -t 10.0.1.10 -k --warmup 5 --timeout 15
```

- `--warmup N` - number of warmup iterations before measuring (default: 3)
- `--timeout N` - connection timeout in seconds (default: 10)

## CLI Reference

```
usage: tls_latency_bench.py [-h] [-t IP_OR_HOST [IP_OR_HOST ...]] [--sni SNI]
                            [-k] [-n ITERATIONS] [--warmup WARMUP]
                            [--timeout TIMEOUT] [--csv FILE]

options:
  -t, --targets IP_OR_HOST [IP_OR_HOST ...]
                        one or more target IPs or hostnames (default: cloudflare.com)
  --sni SNI             SNI hostname for cert validation when targeting IPs
  -k, --insecure        skip TLS certificate verification
  -n, --iterations N    measurement iterations per test case (default: 30)
  --warmup N            warmup iterations before measuring (default: 3)
  --timeout N           connection timeout in seconds (default: 10)
  --csv FILE            export results to CSV file
```

## Output

The script prints a per-target table with statistics for each key exchange:

```
============================================================================================
  Target: 10.0.1.10
============================================================================================
Key Exchange                                 Min     Avg     Med     P95     Max      σ        Δ
--------------------------------------------------------------------------------------------
ECDHE-P256 (TLS 1.2)                       2.31    3.12    2.95    4.10    5.22   0.68   (base)
ECDHE-P384 (TLS 1.2)                       2.88    3.75    3.50    4.95    6.11   0.81  (+20.2%)
X25519 (TLS 1.3)                           1.95    2.60    2.45    3.30    4.15   0.55  (-16.7%)
X25519+MLKEM768 hybrid (TLS 1.3)           2.10    2.85    2.70    3.60    4.50   0.62   (-8.7%)
```

- All times in milliseconds (TLS handshake only, TCP connect time excluded)
- **Δ%** is relative to the first successful test case

## How It Works

Uses `curl -w` to extract precise timing breakdowns:

- `time_connect` - TCP connection established
- `time_appconnect` - TLS handshake completed

**Handshake latency** = `time_appconnect - time_connect` (isolates TLS negotiation from TCP and DNS).

Each test case runs warmup iterations first (discarded) to prime DNS caches and detect unsupported configurations, then N measured iterations to compute min/avg/median/p95/max/stddev.
