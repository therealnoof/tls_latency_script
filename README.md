# TLS Key Exchange Latency Benchmark

Measures TLS handshake latency across classical ECDH (TLS 1.2 & 1.3) and Post-Quantum Cryptography (PQC) hybrid key exchanges. Useful for comparing the overhead of PQC migrations on load balancers, VIPs, and CDN endpoints.

Includes two tools:
- **`tls_latency_bench.py`** — Serial per-handshake latency benchmark across cipher suites
- **`tls_load_test.py`** — Sustained concurrent load test with BIG-IP CPU/memory metrics collection

## Requirements

- **Python 3.10+**
- **curl** built with OpenSSL 3.2+ (for PQC cipher support)
- **requests** library (for load test BIG-IP metrics): `pip install requests`
  - OpenSSL 3.2-3.4: supports `x25519_kyber768` (draft hybrid)
  - OpenSSL 3.5+: supports `X25519MLKEM768`, `SecP256r1MLKEM768` (standardised ML-KEM)
- Network access to the target server(s)

Check your versions:

```bash
curl --version
openssl version
```

> **Note:** Most distro-shipped versions of curl/OpenSSL (e.g. Ubuntu 22.04 ships OpenSSL 3.0.2) do **not** support PQC ciphers. The ECDH tests will still run, but PQC tests will be skipped. See the install guide below to build from source.

## Building curl with OpenSSL 3.5 (PQC Support)

If your system OpenSSL is older than 3.2, you need to build both OpenSSL and curl from source. These steps were tested on Ubuntu 22.04.

### 1. Install build dependencies

```bash
apt-get update
apt-get install -y build-essential pkg-config zlib1g-dev
```

### 2. Build OpenSSL 3.5

```bash
wget https://www.openssl.org/source/openssl-3.5.0.tar.gz
tar xzf openssl-3.5.0.tar.gz
cd openssl-3.5.0
./Configure --prefix=/usr/local/openssl-3.5
make -j$(nproc)
make install
```

### 3. Build curl 8.x against OpenSSL 3.5

```bash
wget https://curl.se/download/curl-8.12.1.tar.gz
tar xzf curl-8.12.1.tar.gz
cd curl-8.12.1

export PKG_CONFIG_PATH=/usr/local/openssl-3.5/lib64/pkgconfig
export LD_LIBRARY_PATH=/usr/local/openssl-3.5/lib64

./configure --with-openssl=/usr/local/openssl-3.5 \
  --without-libpsl \
  --without-brotli \
  --without-zstd \
  --without-libidn2 \
  --without-librtmp \
  --without-nghttp2 \
  --disable-ldap

make -j$(nproc)
make install
```

> **Tip:** If OpenSSL installed its libs to `lib/` instead of `lib64/`, swap `lib64` to `lib` in the export lines above. Check with: `ls /usr/local/openssl-3.5/lib64/libssl.* 2>/dev/null || ls /usr/local/openssl-3.5/lib/libssl.*`

### 4. Prevent system linker from loading custom OpenSSL

> **⚠️ CRITICAL:** Do **not** add `LD_LIBRARY_PATH` to `.bashrc` or any shell profile. Doing so causes system services (sshd, systemd, etc.) to load the custom OpenSSL instead of the distro version, which can **prevent the machine from booting**.

Ensure `/usr/local/lib` is **not** in the system linker config:

```bash
# Check for any config that adds /usr/local/lib to the linker path
grep -r "local" /etc/ld.so.conf.d/

# If /etc/ld.so.conf.d/libc.conf exists and contains /usr/local/lib, remove it:
sudo rm /etc/ld.so.conf.d/libc.conf

# Rebuild linker cache
sudo ldconfig

# Verify system sshd uses the DISTRO OpenSSL (not /usr/local)
ldd /usr/sbin/sshd | grep -E "ssl|crypto"
# Should show /lib/x86_64-linux-gnu/ paths only
```

### 5. Verify (using LD_LIBRARY_PATH for current session only)

Set `LD_LIBRARY_PATH` in the current shell session — **not** in `.bashrc`:

```bash
export LD_LIBRARY_PATH=/usr/local/openssl-3.5/lib64
which curl        # should show /usr/local/bin/curl
curl --version    # should show curl 8.12.1 ... OpenSSL/3.5.0
```

For running the test tools, use the wrapper script (see below) or set `LD_LIBRARY_PATH` inline:

```bash
LD_LIBRARY_PATH=/usr/local/openssl-3.5/lib64 python3 tls_latency_bench.py -t 10.1.10.20 -k
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

## Backend Application (Docker)

A simple nginx container is included in `backend/` for use as an F5 pool member or for direct TLS testing. It listens on HTTP (port 80) and HTTPS (port 443) with a self-signed certificate.

### Install Docker (Ubuntu 22.04)

```bash
# Remove any old versions
apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null

# Install prerequisites
apt-get update
apt-get install -y ca-certificates curl gnupg

# Add Docker's official GPG key and repo
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine and Compose
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Verify
docker --version
docker compose version
```

### Start the backend

```bash
cd backend
docker compose up -d --build
```

### Verify it's running

```bash
# Health check (HTTP)
curl http://localhost/health
# {"status":"ok"}

# TLS check (HTTPS, self-signed cert)
curl -k https://localhost/
# {"service":"tls-latency-backend","proto":"https"}
```

### Endpoints

| Path | Description |
|---|---|
| `GET /` | Returns service info JSON |
| `GET /health` | Health check endpoint (use for F5 pool monitors) |

Both endpoints are available on port 80 (HTTP) and port 443 (HTTPS).

### Using with F5

Point your F5 pool members at the backend's IP on port 80 (if the F5 handles TLS termination) or port 443 (if using SSL bridging). Set the F5 health monitor to `GET /health` on the appropriate port.

## How It Works

Uses `curl -w` to extract precise timing breakdowns:

- `time_connect` - TCP connection established
- `time_appconnect` - TLS handshake completed

**Handshake latency** = `time_appconnect - time_connect` (isolates TLS negotiation from TCP and DNS).

Each test case runs warmup iterations first (discarded) to prime DNS caches and detect unsupported configurations, then N measured iterations to compute min/avg/median/p95/max/stddev.

## Load Testing (tls_load_test.py)

Generates sustained concurrent TLS handshake load against two VIPs (non-PQC vs PQC) while polling BIG-IP CPU, memory, and TMM metrics via iControl REST API. See [LAB_GUIDE.md](LAB_GUIDE.md) for full usage and example output.

```bash
python3 tls_load_test.py \
    --bigip-host 10.1.1.4 --bigip-user admin --bigip-pass admin \
    -k --duration 300 --workers 4 --csv results.csv
```
