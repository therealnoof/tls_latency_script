#!/usr/bin/env python3
"""
TLS Load Test with BIG-IP Metrics Collection
Compares system resource impact of non-PQC vs PQC TLS handshakes under sustained load.

Generates concurrent TLS handshake load via multiprocessing workers, while polling
BIG-IP CPU, memory, TMM, and SSL stats via iControl REST API. Runs non-PQC and PQC
scenarios sequentially, then prints a side-by-side comparison report.

Supports two handshake engines:
  - native: Python ssl module with direct socket control (high throughput, 5-10x faster)
  - curl:   curl subprocess per handshake (legacy, lower throughput)

Requirements:
  - Python 3.10+
  - For native engine: Python linked against OpenSSL 3.2+ (3.5+ for ML-KEM PQC)
  - For curl engine:   curl built with OpenSSL 3.2+ (3.5+ for ML-KEM PQC ciphers)
  - requests library: pip install requests
  - Network access to BIG-IP management interface and VIPs

Usage:
  python3 tls_load_test.py --bigip-host 10.1.1.4 --bigip-user admin --bigip-pass admin -k
  python3 tls_load_test.py --engine native --workers 16 --duration 120 --csv results.csv
  python3 tls_load_test.py --engine curl --workers 4 -k   # legacy curl mode
"""

import argparse
import ctypes
import ctypes.util
import json
import multiprocessing
import os
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERROR: 'requests' library required. Install with: pip install requests",
          file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class LoadTestScenario:
    label: str
    target: str
    tls_version: str
    groups: str
    cipher: str = ""
    tls13_cipher: str = ""


@dataclass
class HandshakeResult:
    timestamp: float
    latency_ms: float
    success: bool


@dataclass
class BigIPMetricSample:
    timestamp: float
    cpu_utilization: float
    memory_used_pct: float
    tmm_cpu_pct: float
    active_ssl_connections: int
    ssl_transactions_per_sec: float
    throughput_in_mbps: float = 0.0
    throughput_out_mbps: float = 0.0


@dataclass
class ScenarioReport:
    scenario: LoadTestScenario
    duration_seconds: float
    total_handshakes: int
    successful_handshakes: int
    failed_handshakes: int
    handshakes_per_second: float
    latency_min_ms: float
    latency_avg_ms: float
    latency_median_ms: float
    latency_p95_ms: float
    latency_max_ms: float
    latency_stddev_ms: float
    bigip_metrics: list = field(default_factory=list)
    bigip_cpu_avg: float = 0.0
    bigip_cpu_max: float = 0.0
    bigip_mem_avg: float = 0.0
    bigip_mem_max: float = 0.0
    bigip_tmm_cpu_avg: float = 0.0
    bigip_tmm_cpu_max: float = 0.0
    bigip_ssl_tps_avg: float = 0.0
    bigip_ssl_tps_max: float = 0.0
    bigip_throughput_in_avg_mbps: float = 0.0
    bigip_throughput_in_max_mbps: float = 0.0
    bigip_throughput_out_avg_mbps: float = 0.0
    bigip_throughput_out_max_mbps: float = 0.0


# ---------------------------------------------------------------------------
# curl handshake (adapted from tls_latency_bench.py)
# ---------------------------------------------------------------------------

CURL_WRITE_OUT = json.dumps({
    "time_namelookup": "%{time_namelookup}",
    "time_connect": "%{time_connect}",
    "time_appconnect": "%{time_appconnect}",
})


def run_single_handshake(target, tls_version, groups, cipher="",
                         tls13_cipher="", timeout=10, insecure=False,
                         sni=""):
    """Execute one TLS handshake via curl. Returns a HandshakeResult."""
    cmd = [
        "curl", "-so", "/dev/null",
        "-w", CURL_WRITE_OUT,
        "--connect-timeout", str(timeout),
    ]

    if insecure:
        cmd.append("-k")

    if sni:
        cmd += ["--resolve", f"{sni}:443:{target}"]
        url_host = sni
    else:
        url_host = target

    if tls_version == "1.2":
        cmd += ["--tlsv1.2", "--tls-max", "1.2"]
    else:
        cmd += ["--tlsv1.3", "--tls-max", "1.3"]

    if cipher:
        cmd += ["--ciphers", cipher]
    if tls13_cipher:
        cmd += ["--tls13-ciphers", tls13_cipher]
    if groups:
        cmd += ["--curves", groups]

    cmd.append(f"https://{url_host}/")

    ts = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        data = json.loads(r.stdout)
        tcp_connect = float(data["time_connect"])
        tls_done = float(data["time_appconnect"])
        if tls_done <= 0 or tcp_connect <= 0:
            return HandshakeResult(timestamp=ts, latency_ms=0, success=False)
        latency = (tls_done - tcp_connect) * 1000
        return HandshakeResult(timestamp=ts, latency_ms=latency, success=True)
    except (json.JSONDecodeError, KeyError, ValueError, subprocess.TimeoutExpired):
        return HandshakeResult(timestamp=ts, latency_ms=0, success=False)


# ---------------------------------------------------------------------------
# Native SSL engine — bypasses curl subprocess for higher throughput
# ---------------------------------------------------------------------------

def _get_openssl_version_tuple():
    """Parse the OpenSSL version from ssl.OPENSSL_VERSION into (major, minor, patch)."""
    try:
        parts = ssl.OPENSSL_VERSION.split()
        if len(parts) >= 2:
            nums = parts[1].split(".")
            return (int(nums[0]), int(nums[1]), int(nums[2]) if len(nums) > 2 else 0)
    except (IndexError, ValueError):
        pass
    return (0, 0, 0)


def _load_libssl():
    """Locate and load the libssl shared library that Python's ssl module uses.

    Tries multiple strategies since ctypes.util.find_library() often fails
    on systems with custom OpenSSL builds (e.g. /usr/local/openssl-3.5).

    Returns (handle, path_info) or (None, reason).
    """
    # Strategy 1: Read /proc/self/maps to find the exact libssl loaded by
    # Python's _ssl module. This is the most reliable method on Linux since
    # it finds the actual library in memory regardless of LD_LIBRARY_PATH
    # or ldconfig configuration.
    try:
        with open("/proc/self/maps", "r") as f:
            for line in f:
                if "libssl" in line and ".so" in line:
                    path = line.strip().split()[-1]
                    if path.startswith("/") and os.path.isfile(path):
                        try:
                            handle = ctypes.CDLL(path)
                            return handle, path
                        except OSError:
                            continue
    except (OSError, IOError):
        pass  # Not on Linux, or /proc not available

    # Strategy 2: Try common .so names (may load system default, not custom)
    for name in ("libssl.so.3", "libssl.so", "libssl.3.dylib"):
        try:
            handle = ctypes.CDLL(name)
            return handle, name
        except OSError:
            continue

    # Strategy 3: ctypes.util.find_library (works when ldconfig is up to date)
    try:
        libssl_name = ctypes.util.find_library("ssl")
        if libssl_name:
            handle = ctypes.CDLL(libssl_name)
            return handle, libssl_name
    except OSError:
        pass

    return None, "all strategies failed"


# SSL_CTX_ctrl command code for setting key exchange groups.
# SSL_CTX_set1_groups_list(ctx, str) is a MACRO that expands to:
#   SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, str)
# We must call SSL_CTX_ctrl directly because macros don't exist as
# symbols in the shared library and ctypes can't resolve them.
_SSL_CTRL_SET_GROUPS_LIST = 92


def _try_set_groups_ctypes(ctx, groups_str):
    """Set key exchange groups via ctypes calling SSL_CTX_ctrl.

    Python <3.13 set_ecdh_curve() uses the old EC_KEY API which does not
    support X25519 or PQC groups. This function calls SSL_CTX_ctrl() with
    SSL_CTRL_SET_GROUPS_LIST (92) directly — the same call that the
    SSL_CTX_set1_groups_list macro expands to.

    Only attempted when Python's ssl module is linked against OpenSSL 3.2+.
    Returns True on success, False on failure.
    """
    # Only safe when Python's ssl is linked against OpenSSL (not LibreSSL)
    if "LibreSSL" in ssl.OPENSSL_VERSION:
        return False
    major, minor, _ = _get_openssl_version_tuple()
    if major < 3 or (major == 3 and minor < 2):
        return False

    try:
        libssl, _path = _load_libssl()
        if not libssl:
            return False

        # long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
        func = libssl.SSL_CTX_ctrl
        func.argtypes = [ctypes.c_void_p, ctypes.c_int,
                         ctypes.c_long, ctypes.c_char_p]
        func.restype = ctypes.c_long

        # Extract the SSL_CTX* pointer from the Python SSLContext object.
        # In CPython, PySSLContext layout is:
        #   PyObject_HEAD  →  ob_refcnt (Py_ssize_t) + ob_type (pointer)
        #   SSL_CTX *ctx   →  the pointer we need
        # On 64-bit Linux: offset = 16 bytes (2 × 8-byte pointers)
        ptr_size = ctypes.sizeof(ctypes.c_void_p)
        offset = 2 * ptr_size  # skip ob_refcnt + ob_type
        ssl_ctx_ptr = ctypes.c_void_p.from_address(id(ctx) + offset).value
        if not ssl_ctx_ptr:
            return False

        result = func(ssl_ctx_ptr, _SSL_CTRL_SET_GROUPS_LIST, 0,
                      groups_str.encode("ascii"))
        return result == 1
    except (OSError, AttributeError, TypeError, ValueError):
        return False


def _create_ssl_context(tls_version, groups, cipher="", tls13_cipher="",
                        insecure=False):
    """Create a reusable SSLContext configured for the requested TLS parameters.

    Raises RuntimeError if the requested key exchange groups are not supported.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Certificate verification
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.load_default_certs()

    # Pin TLS version
    if tls_version == "1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Set cipher suites (TLS 1.2)
    if cipher:
        ctx.set_ciphers(cipher)

    # Set key exchange groups
    if groups:
        try:
            # Python 3.10+ with OpenSSL 3.x: set_ecdh_curve calls
            # SSL_CTX_set1_groups_list internally, supporting PQC names
            ctx.set_ecdh_curve(groups)
        except (ValueError, ssl.SSLError):
            # Fallback: use ctypes to call SSL_CTX_set1_groups_list directly
            if not _try_set_groups_ctypes(ctx, groups):
                raise RuntimeError(
                    f"Cannot set key exchange group '{groups}'. "
                    f"Python ssl is linked against {ssl.OPENSSL_VERSION}. "
                    f"PQC groups require OpenSSL 3.2+ (3.5+ for ML-KEM). "
                    f"Use --engine curl as a fallback."
                )

    return ctx


def run_native_handshake(ctx, target, sni="", timeout=10):
    """Execute one TLS handshake using Python's ssl module. Returns HandshakeResult.

    The SSLContext is pre-built and reused across calls — only the socket
    connect + TLS handshake are performed per invocation, which eliminates
    the subprocess overhead of curl.
    """
    hostname = sni if sni else target
    ts = time.time()
    sock = None
    ssl_sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # SO_LINGER with timeout=0: sends RST on close instead of FIN, which
        # avoids TIME_WAIT state. Critical at high throughput to prevent
        # ephemeral port exhaustion (28k ports / 60s TIME_WAIT = max ~470/sec
        # without this).
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))

        # TCP connect (not timed — we only measure the TLS handshake)
        sock.connect((target, 443))

        # Wrap socket and perform TLS handshake (TIMED)
        ssl_sock = ctx.wrap_socket(sock, server_hostname=hostname,
                                   do_handshake_on_connect=False)
        tls_start = time.perf_counter()
        ssl_sock.do_handshake()
        tls_end = time.perf_counter()

        latency_ms = (tls_end - tls_start) * 1000.0
        return HandshakeResult(timestamp=ts, latency_ms=latency_ms, success=True)

    except (ssl.SSLError, socket.timeout, socket.error,
            ConnectionRefusedError, OSError):
        return HandshakeResult(timestamp=ts, latency_ms=0, success=False)
    finally:
        # Close whichever socket layer exists; ssl_sock.close() closes
        # the underlying sock too.
        to_close = ssl_sock if ssl_sock else sock
        if to_close:
            try:
                to_close.close()
            except OSError:
                pass


def probe_native_support(groups_list):
    """Test whether the native SSL engine supports the requested key exchange groups.

    Args:
        groups_list: list of group strings to test (e.g. ["X25519", "X25519MLKEM768"])

    Returns:
        (supported: bool, details: str) — True if ALL groups are supported natively.
    """
    unsupported = []
    errors = []
    for groups_str in groups_list:
        try:
            _create_ssl_context(tls_version="1.3", groups=groups_str, insecure=True)
        except (RuntimeError, ssl.SSLError, Exception) as e:
            unsupported.append(groups_str)
            errors.append(f"{groups_str}: {e}")

    if not unsupported:
        return True, "All requested groups supported natively"

    # Print diagnostic details to help troubleshoot
    print(f"  Native SSL probe details:", file=sys.stderr)
    print(f"    Python ssl linked: {ssl.OPENSSL_VERSION}", file=sys.stderr)
    print(f"    Python version:    {sys.version.split()[0]}", file=sys.stderr)
    print(f"    TLS 1.3 support:   {getattr(ssl, 'HAS_TLSv1_3', False)}",
          file=sys.stderr)
    # Check if ctypes can find libssl
    libssl, libssl_path = _load_libssl()
    if libssl:
        print(f"    ctypes libssl:     {libssl_path}", file=sys.stderr)
        has_ctrl = hasattr(libssl, "SSL_CTX_ctrl")
        print(f"    SSL_CTX_ctrl:      {'found' if has_ctrl else 'NOT FOUND'}",
              file=sys.stderr)
    else:
        print(f"    ctypes libssl:     FAILED ({libssl_path})", file=sys.stderr)
    for err in errors:
        print(f"    Error: {err}", file=sys.stderr)

    return False, f"Unsupported groups: {', '.join(unsupported)}"


# ---------------------------------------------------------------------------
# Multiprocessing worker
# ---------------------------------------------------------------------------

def _run_batch_handshake(ctx, target, sni, timeout, batch_size):
    """Run a batch of concurrent native handshakes using threads within a worker.

    Each handshake gets its own thread and socket. The SSLContext is shared
    (thread-safe in OpenSSL 3.x). Returns a list of HandshakeResults.
    """
    results = []
    lock = threading.Lock()

    def _do_one():
        r = run_native_handshake(ctx=ctx, target=target, sni=sni, timeout=timeout)
        with lock:
            results.append(r)

    threads = []
    for _ in range(batch_size):
        t = threading.Thread(target=_do_one)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=timeout + 5)
    return results


def worker_loop(target, tls_version, groups, cipher, tls13_cipher,
                duration_seconds, insecure, sni, timeout, results_file,
                engine="native", batch_size=1):
    """Worker process: continuously perform TLS handshakes for the given duration.

    Results are written to a temporary file (one CSV line per result) to avoid
    multiprocessing.Queue pipe buffer limits that can cause workers to hang.

    When engine='native', creates a single SSLContext upfront and reuses it for
    all handshakes — eliminating curl subprocess overhead entirely.

    When batch_size > 1 (native only), each iteration fires batch_size concurrent
    handshakes using threads, multiplying throughput per worker.
    """
    end_time = time.time() + duration_seconds

    if engine == "native":
        # Build SSLContext once for this worker — reused for every handshake
        ctx = _create_ssl_context(
            tls_version=tls_version, groups=groups,
            cipher=cipher, tls13_cipher=tls13_cipher,
            insecure=insecure,
        )
        if batch_size > 1:
            # Threaded batch mode: fire batch_size concurrent handshakes per iteration
            with open(results_file, "w") as f:
                while time.time() < end_time:
                    batch_results = _run_batch_handshake(
                        ctx, target, sni, timeout, batch_size,
                    )
                    for result in batch_results:
                        f.write(f"{result.timestamp},{result.latency_ms},"
                                f"{result.success}\n")
        else:
            # Sequential mode (batch_size=1)
            with open(results_file, "w") as f:
                while time.time() < end_time:
                    result = run_native_handshake(
                        ctx=ctx, target=target, sni=sni, timeout=timeout,
                    )
                    f.write(f"{result.timestamp},{result.latency_ms},"
                            f"{result.success}\n")
    else:
        # Legacy curl subprocess engine (no batching)
        with open(results_file, "w") as f:
            while time.time() < end_time:
                result = run_single_handshake(
                    target=target, tls_version=tls_version, groups=groups,
                    cipher=cipher, tls13_cipher=tls13_cipher,
                    timeout=timeout, insecure=insecure, sni=sni,
                )
                f.write(f"{result.timestamp},{result.latency_ms},"
                        f"{result.success}\n")


# ---------------------------------------------------------------------------
# BIG-IP iControl REST metrics collection
# ---------------------------------------------------------------------------

def _parse_cpu(cpu_data):
    """Extract average CPU utilization from /mgmt/tm/sys/cpu response."""
    try:
        entries = cpu_data.get("entries", {})
        cpu_totals = []
        for _key, val in entries.items():
            nested = val.get("nestedStats", {}).get("entries", {})
            # Look for per-CPU entries inside nested structure
            for _sub_key, sub_val in nested.items():
                if isinstance(sub_val, dict) and "nestedStats" in sub_val:
                    cpu_entries = sub_val["nestedStats"].get("entries", {})
                    one_min_sys = cpu_entries.get("oneMinAvgSystem", {}).get("value", 0)
                    one_min_user = cpu_entries.get("oneMinAvgUser", {}).get("value", 0)
                    if one_min_sys or one_min_user:
                        cpu_totals.append(int(one_min_sys) + int(one_min_user))
        return statistics.mean(cpu_totals) if cpu_totals else 0.0
    except (KeyError, TypeError, ValueError):
        return 0.0


def _parse_memory(mem_data):
    """Extract memory usage percentage from /mgmt/tm/sys/memory response."""
    try:
        entries = mem_data.get("entries", {})
        for _key, val in entries.items():
            nested = val.get("nestedStats", {}).get("entries", {})
            # Look for host memory entry
            for _sub_key, sub_val in nested.items():
                if isinstance(sub_val, dict) and "nestedStats" in sub_val:
                    mem_entries = sub_val["nestedStats"].get("entries", {})
                    mem_total = mem_entries.get("memoryTotal", {}).get("value", 0)
                    mem_used = mem_entries.get("memoryUsed", {}).get("value", 0)
                    if int(mem_total) > 0:
                        return (int(mem_used) / int(mem_total)) * 100
        return 0.0
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return 0.0


def _parse_tmm_cpu(tmm_data):
    """Extract average TMM CPU utilization from /mgmt/tm/sys/tmm-info response."""
    try:
        entries = tmm_data.get("entries", {})
        ratios = []
        for _key, val in entries.items():
            nested = val.get("nestedStats", {}).get("entries", {})
            ratio = nested.get("oneMinAvgUsageRatio", {}).get("value", 0)
            if ratio:
                ratios.append(int(ratio))
        return statistics.mean(ratios) if ratios else 0.0
    except (KeyError, TypeError, ValueError):
        return 0.0


def _parse_ssl_stats(perf_data):
    """Extract SSL and throughput stats from /mgmt/tm/sys/performance/all-stats."""
    ssl_conns = 0
    ssl_tps = 0.0
    throughput_in_mbps = 0.0
    throughput_out_mbps = 0.0
    try:
        entries = perf_data.get("entries", {})
        for key, val in entries.items():
            nested = val.get("nestedStats", {}).get("entries", {})
            key_lower = key.lower()

            # SSL metrics
            if "ssl" in key_lower and "transaction" in key_lower:
                current = nested.get("current", {}).get("value", 0)
                ssl_tps = float(current)
            elif "ssl" in key_lower and ("conn" in key_lower or "concurrent" in key_lower):
                current = nested.get("current", {}).get("value", 0)
                ssl_conns = int(current)

            # Throughput metrics (reported in bits/sec by BIG-IP)
            if "throughput" in key_lower or "bandwidth" in key_lower:
                current = nested.get("current", {}).get("value", 0)
                if "in" in key_lower and "out" not in key_lower:
                    throughput_in_mbps = float(current) / 1_000_000  # bits → Mbps
                elif "out" in key_lower:
                    throughput_out_mbps = float(current) / 1_000_000  # bits → Mbps
    except (KeyError, TypeError, ValueError):
        pass
    return ssl_conns, ssl_tps, throughput_in_mbps, throughput_out_mbps


def fetch_bigip_stats(session, base_url):
    """Fetch CPU, memory, TMM, and SSL stats from BIG-IP. Returns BigIPMetricSample or None."""
    try:
        cpu_resp = session.get(f"{base_url}/sys/cpu", timeout=10)
        cpu_resp.raise_for_status()
        cpu_data = cpu_resp.json()

        mem_resp = session.get(f"{base_url}/sys/memory", timeout=10)
        mem_resp.raise_for_status()
        mem_data = mem_resp.json()

        tmm_resp = session.get(f"{base_url}/sys/tmm-info", timeout=10)
        tmm_resp.raise_for_status()
        tmm_data = tmm_resp.json()

        perf_resp = session.get(f"{base_url}/sys/performance/all-stats", timeout=10)
        perf_resp.raise_for_status()
        perf_data = perf_resp.json()

        cpu_pct = _parse_cpu(cpu_data)
        mem_pct = _parse_memory(mem_data)
        tmm_cpu = _parse_tmm_cpu(tmm_data)
        ssl_conns, ssl_tps, tp_in, tp_out = _parse_ssl_stats(perf_data)

        return BigIPMetricSample(
            timestamp=time.time(),
            cpu_utilization=cpu_pct,
            memory_used_pct=mem_pct,
            tmm_cpu_pct=tmm_cpu,
            active_ssl_connections=ssl_conns,
            ssl_transactions_per_sec=ssl_tps,
            throughput_in_mbps=tp_in,
            throughput_out_mbps=tp_out,
        )
    except requests.RequestException as e:
        print(f"  WARNING: BIG-IP metric poll failed: {e}", file=sys.stderr)
        return None


def collect_bigip_metrics(bigip_host, username, password, poll_interval,
                          stop_event, metrics_list):
    """Background thread: polls BIG-IP iControl REST at regular intervals."""
    session = requests.Session()
    session.auth = (username, password)
    session.verify = False
    base_url = f"https://{bigip_host}/mgmt/tm"

    while not stop_event.is_set():
        sample = fetch_bigip_stats(session, base_url)
        if sample:
            metrics_list.append(sample)
        stop_event.wait(poll_interval)


# ---------------------------------------------------------------------------
# Scenario orchestration
# ---------------------------------------------------------------------------

def run_load_scenario(scenario, workers, duration, insecure, sni, timeout,
                      bigip_host, bigip_user, bigip_pass, poll_interval,
                      engine="native", batch_size=1):
    """Run a complete load test scenario: spawn workers + collect BIG-IP metrics."""
    effective_conns = workers * batch_size
    w = 80
    print(f"\n{'=' * w}")
    print(f"  Scenario: {scenario.label}")
    print(f"  Target: {scenario.target} | Groups: {scenario.groups}")
    print(f"  Workers: {workers} | Batch: {batch_size} | "
          f"Effective concurrency: {effective_conns} | Engine: {engine}")
    print(f"  Duration: {duration}s")
    print(f"{'=' * w}")

    # Verify the VIP is reachable with a quick handshake
    print("  Verifying VIP connectivity...", end=" ")
    probe = run_single_handshake(
        target=scenario.target, tls_version=scenario.tls_version,
        groups=scenario.groups, cipher=scenario.cipher,
        tls13_cipher=scenario.tls13_cipher, timeout=timeout,
        insecure=insecure, sni=sni,
    )
    if not probe.success:
        print("FAILED")
        print(f"  ERROR: Cannot complete TLS handshake to {scenario.target}")
        print("  Skipping this scenario.")
        return None
    print(f"OK ({probe.latency_ms:.2f}ms)")

    # Start BIG-IP metrics collection thread
    metrics_list = []
    stop_event = threading.Event()
    metrics_thread = threading.Thread(
        target=collect_bigip_metrics,
        args=(bigip_host, bigip_user, bigip_pass, poll_interval,
              stop_event, metrics_list),
        daemon=True,
    )
    metrics_thread.start()

    # Spawn worker processes — each writes results to a temp file to avoid
    # multiprocessing.Queue pipe buffer limits that cause hangs.
    tmp_dir = tempfile.mkdtemp(prefix="tls_load_")
    result_files = []
    processes = []
    start_time = time.time()

    for i in range(workers):
        results_file = os.path.join(tmp_dir, f"worker_{i}.csv")
        result_files.append(results_file)
        p = multiprocessing.Process(
            target=worker_loop,
            args=(scenario.target, scenario.tls_version, scenario.groups,
                  scenario.cipher, scenario.tls13_cipher, duration,
                  insecure, sni, timeout, results_file, engine,
                  batch_size),
        )
        processes.append(p)
        p.start()

    # Progress reporting while workers are running
    print(f"  Load test running...")
    deadline = start_time + duration + 60  # hard timeout: duration + 60s buffer
    while any(p.is_alive() for p in processes):
        elapsed = time.time() - start_time
        remaining = max(0, duration - elapsed)
        if metrics_list:
            m = metrics_list[-1]
            latest_tmm = f"{m.tmm_cpu_pct:.0f}"
            latest_tps = f"{m.ssl_transactions_per_sec:.0f}"
            latest_tp = f"{m.throughput_in_mbps + m.throughput_out_mbps:.0f}"
        else:
            latest_tmm = latest_tps = latest_tp = "N/A"
        print(f"\r  [{elapsed:>5.0f}s / {duration}s] "
              f"TMM: {latest_tmm}%  SSL TPS: {latest_tps}  "
              f"Throughput: {latest_tp} Mbps  "
              f"Remaining: {remaining:.0f}s   ", end="", flush=True)
        # Short sleep so we detect worker completion quickly
        time.sleep(2)
        # Hard timeout safety
        if time.time() > deadline:
            print("\n  WARNING: Workers exceeded deadline, terminating...")
            for p in processes:
                if p.is_alive():
                    p.terminate()
            break

    # Wait for all workers to finish
    for p in processes:
        p.join(timeout=10)

    # Stop metrics collection
    stop_event.set()
    metrics_thread.join(timeout=5)

    elapsed = time.time() - start_time
    print(f"\r  Completed in {elapsed:.1f}s" + " " * 50)

    # Collect results from worker temp files
    all_results = []
    for results_file in result_files:
        try:
            with open(results_file, "r") as f:
                for line in f:
                    parts = line.strip().split(",")
                    if len(parts) == 3:
                        all_results.append(HandshakeResult(
                            timestamp=float(parts[0]),
                            latency_ms=float(parts[1]),
                            success=parts[2] == "True",
                        ))
            os.remove(results_file)
        except (OSError, ValueError):
            pass
    try:
        os.rmdir(tmp_dir)
    except OSError:
        pass

    return compute_scenario_report(scenario, all_results, metrics_list, elapsed)


def compute_scenario_report(scenario, results, metrics, elapsed):
    """Aggregate raw handshake results and BIG-IP metrics into a report."""
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    latencies = [r.latency_ms for r in successful]

    if latencies:
        s = sorted(latencies)
        lat_min = min(latencies)
        lat_avg = statistics.mean(latencies)
        lat_med = statistics.median(latencies)
        lat_p95 = s[int(len(s) * 0.95)] if len(s) >= 20 else max(latencies)
        lat_max = max(latencies)
        lat_std = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
    else:
        lat_min = lat_avg = lat_med = lat_p95 = lat_max = lat_std = 0.0

    cpu_vals = [m.cpu_utilization for m in metrics]
    mem_vals = [m.memory_used_pct for m in metrics]
    tmm_vals = [m.tmm_cpu_pct for m in metrics]
    ssl_tps_vals = [m.ssl_transactions_per_sec for m in metrics]
    tp_in_vals = [m.throughput_in_mbps for m in metrics]
    tp_out_vals = [m.throughput_out_mbps for m in metrics]

    return ScenarioReport(
        scenario=scenario,
        duration_seconds=elapsed,
        total_handshakes=len(results),
        successful_handshakes=len(successful),
        failed_handshakes=len(failed),
        handshakes_per_second=len(successful) / elapsed if elapsed > 0 else 0,
        latency_min_ms=lat_min,
        latency_avg_ms=lat_avg,
        latency_median_ms=lat_med,
        latency_p95_ms=lat_p95,
        latency_max_ms=lat_max,
        latency_stddev_ms=lat_std,
        bigip_metrics=metrics,
        bigip_cpu_avg=statistics.mean(cpu_vals) if cpu_vals else 0.0,
        bigip_cpu_max=max(cpu_vals) if cpu_vals else 0.0,
        bigip_mem_avg=statistics.mean(mem_vals) if mem_vals else 0.0,
        bigip_mem_max=max(mem_vals) if mem_vals else 0.0,
        bigip_tmm_cpu_avg=statistics.mean(tmm_vals) if tmm_vals else 0.0,
        bigip_tmm_cpu_max=max(tmm_vals) if tmm_vals else 0.0,
        bigip_ssl_tps_avg=statistics.mean(ssl_tps_vals) if ssl_tps_vals else 0.0,
        bigip_ssl_tps_max=max(ssl_tps_vals) if ssl_tps_vals else 0.0,
        bigip_throughput_in_avg_mbps=statistics.mean(tp_in_vals) if tp_in_vals else 0.0,
        bigip_throughput_in_max_mbps=max(tp_in_vals) if tp_in_vals else 0.0,
        bigip_throughput_out_avg_mbps=statistics.mean(tp_out_vals) if tp_out_vals else 0.0,
        bigip_throughput_out_max_mbps=max(tp_out_vals) if tp_out_vals else 0.0,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_comparison_report(reports):
    """Print a side-by-side comparison of all scenario reports."""
    w = 80
    print(f"\n{'=' * w}")
    print(f"  TLS Load Test — Comparison Report")
    print(f"{'=' * w}")

    for report in reports:
        tp_in = report.bigip_throughput_in_avg_mbps
        tp_out = report.bigip_throughput_out_avg_mbps
        tp_in_max = report.bigip_throughput_in_max_mbps
        tp_out_max = report.bigip_throughput_out_max_mbps

        print(f"\n  {report.scenario.label} ({report.scenario.target})")
        print(f"  {'-' * 60}")
        print(f"  Duration:           {report.duration_seconds:.1f}s")
        print(f"  Total handshakes:   {report.total_handshakes:,}")
        print(f"  Successful:         {report.successful_handshakes:,}")
        print(f"  Failed:             {report.failed_handshakes:,}")
        print(f"  Throughput:         {report.handshakes_per_second:.1f} handshakes/sec")
        print(f"  Latency (ms):       min={report.latency_min_ms:.2f}  "
              f"avg={report.latency_avg_ms:.2f}  "
              f"med={report.latency_median_ms:.2f}  "
              f"p95={report.latency_p95_ms:.2f}  "
              f"max={report.latency_max_ms:.2f}")
        print(f"  BIG-IP CPU:         avg={report.bigip_cpu_avg:.1f}%  "
              f"max={report.bigip_cpu_max:.1f}%")
        print(f"  BIG-IP TMM CPU:     avg={report.bigip_tmm_cpu_avg:.1f}%  "
              f"max={report.bigip_tmm_cpu_max:.1f}%")
        print(f"  BIG-IP Memory:      avg={report.bigip_mem_avg:.1f}%  "
              f"max={report.bigip_mem_max:.1f}%")
        print(f"  BIG-IP SSL TPS:     avg={report.bigip_ssl_tps_avg:.0f}  "
              f"max={report.bigip_ssl_tps_max:.0f}")
        print(f"  BIG-IP Throughput:  in={tp_in:.1f} Mbps (max {tp_in_max:.1f})  "
              f"out={tp_out:.1f} Mbps (max {tp_out_max:.1f})")

    # Delta comparison
    if len(reports) == 2:
        base, pqc = reports[0], reports[1]
        print(f"\n  {'=' * 60}")
        print(f"  PQC Impact (relative to {base.scenario.label})")
        print(f"  {'-' * 60}")

        if base.handshakes_per_second > 0:
            tput_delta = ((pqc.handshakes_per_second - base.handshakes_per_second)
                          / base.handshakes_per_second * 100)
            print(f"  Throughput:         {tput_delta:+.1f}%")

        if base.latency_avg_ms > 0:
            lat_delta = ((pqc.latency_avg_ms - base.latency_avg_ms)
                         / base.latency_avg_ms * 100)
            print(f"  Avg latency:        {lat_delta:+.1f}%")

        cpu_delta = pqc.bigip_cpu_avg - base.bigip_cpu_avg
        print(f"  BIG-IP CPU (avg):   {cpu_delta:+.1f} percentage points")

        tmm_delta = pqc.bigip_tmm_cpu_avg - base.bigip_tmm_cpu_avg
        print(f"  BIG-IP TMM CPU:     {tmm_delta:+.1f} percentage points")

        mem_delta = pqc.bigip_mem_avg - base.bigip_mem_avg
        print(f"  BIG-IP Memory:      {mem_delta:+.1f} percentage points")

        if base.bigip_ssl_tps_avg > 0:
            tps_delta = ((pqc.bigip_ssl_tps_avg - base.bigip_ssl_tps_avg)
                         / base.bigip_ssl_tps_avg * 100)
            print(f"  SSL TPS:            {tps_delta:+.1f}%")

        base_tp = base.bigip_throughput_in_avg_mbps + base.bigip_throughput_out_avg_mbps
        pqc_tp = pqc.bigip_throughput_in_avg_mbps + pqc.bigip_throughput_out_avg_mbps
        if base_tp > 0:
            tp_delta = ((pqc_tp - base_tp) / base_tp * 100)
            print(f"  Throughput:         {tp_delta:+.1f}% "
                  f"({base_tp:.1f} → {pqc_tp:.1f} Mbps)")

    print(f"\n{'=' * w}")


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def export_csv(reports, path):
    """Export summary and time-series BIG-IP metrics to CSV files."""
    base = path.replace(".csv", "") if path.endswith(".csv") else path

    # Summary CSV
    summary_path = f"{base}_summary.csv"
    with open(summary_path, "w") as f:
        f.write(
            "scenario,target,groups,duration_s,total_handshakes,successful,"
            "failed,handshakes_per_sec,"
            "lat_min_ms,lat_avg_ms,lat_median_ms,lat_p95_ms,lat_max_ms,lat_stddev_ms,"
            "bigip_cpu_avg,bigip_cpu_max,bigip_mem_avg,bigip_mem_max,"
            "bigip_tmm_cpu_avg,bigip_tmm_cpu_max,"
            "bigip_ssl_tps_avg,bigip_ssl_tps_max,"
            "bigip_throughput_in_avg_mbps,bigip_throughput_in_max_mbps,"
            "bigip_throughput_out_avg_mbps,bigip_throughput_out_max_mbps\n"
        )
        for r in reports:
            f.write(
                f'"{r.scenario.label}",{r.scenario.target},{r.scenario.groups},'
                f'{r.duration_seconds:.1f},{r.total_handshakes},'
                f'{r.successful_handshakes},{r.failed_handshakes},'
                f'{r.handshakes_per_second:.1f},'
                f'{r.latency_min_ms:.2f},{r.latency_avg_ms:.2f},'
                f'{r.latency_median_ms:.2f},{r.latency_p95_ms:.2f},'
                f'{r.latency_max_ms:.2f},{r.latency_stddev_ms:.2f},'
                f'{r.bigip_cpu_avg:.1f},{r.bigip_cpu_max:.1f},'
                f'{r.bigip_mem_avg:.1f},{r.bigip_mem_max:.1f},'
                f'{r.bigip_tmm_cpu_avg:.1f},{r.bigip_tmm_cpu_max:.1f},'
                f'{r.bigip_ssl_tps_avg:.0f},{r.bigip_ssl_tps_max:.0f},'
                f'{r.bigip_throughput_in_avg_mbps:.1f},{r.bigip_throughput_in_max_mbps:.1f},'
                f'{r.bigip_throughput_out_avg_mbps:.1f},{r.bigip_throughput_out_max_mbps:.1f}\n'
            )
    print(f"  Summary:     {summary_path}")

    # Time-series metrics CSV
    metrics_path = f"{base}_metrics.csv"
    with open(metrics_path, "w") as f:
        f.write(
            "scenario,timestamp,elapsed_s,cpu_pct,memory_pct,"
            "tmm_cpu_pct,active_ssl_conns,ssl_tps,"
            "throughput_in_mbps,throughput_out_mbps\n"
        )
        for r in reports:
            start_ts = r.bigip_metrics[0].timestamp if r.bigip_metrics else 0
            for m in r.bigip_metrics:
                elapsed = m.timestamp - start_ts
                f.write(
                    f'"{r.scenario.label}",{m.timestamp:.3f},{elapsed:.1f},'
                    f'{m.cpu_utilization:.1f},{m.memory_used_pct:.1f},'
                    f'{m.tmm_cpu_pct:.1f},{m.active_ssl_connections},'
                    f'{m.ssl_transactions_per_sec:.1f},'
                    f'{m.throughput_in_mbps:.1f},{m.throughput_out_mbps:.1f}\n'
                )
    print(f"  Time-series: {metrics_path}")


# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

def check_prerequisites(engine):
    """Print curl, OpenSSL, and Python SSL versions."""
    # Python ssl module info (always relevant)
    print(f"  Python {sys.version.split()[0]} ssl: {ssl.OPENSSL_VERSION}")
    has_tls13 = getattr(ssl, "HAS_TLSv1_3", False)
    print(f"  TLS 1.3 support: {'yes' if has_tls13 else 'no'}")

    if engine == "curl":
        try:
            r = subprocess.run(["curl", "--version"], capture_output=True, text=True)
            first_line = r.stdout.splitlines()[0] if r.stdout else "curl: unknown"
            print(f"  {first_line}")
        except FileNotFoundError:
            print("ERROR: curl not found (required for --engine curl).",
                  file=sys.stderr)
            sys.exit(1)

    try:
        r = subprocess.run(["openssl", "version"], capture_output=True, text=True)
        print(f"  System OpenSSL: {r.stdout.strip()}")
    except FileNotFoundError:
        print("  openssl CLI not found (optional)")


def verify_bigip_connection(host, username, password):
    """Verify BIG-IP iControl REST connectivity."""
    print(f"  Connecting to BIG-IP at {host}...", end=" ")
    url = f"https://{host}/mgmt/tm/sys/version"
    try:
        resp = requests.get(url, auth=(username, password), verify=False, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        entries = data.get("entries", {})
        for _key, val in entries.items():
            props = val.get("nestedStats", {}).get("entries", {})
            version = props.get("Version", {}).get("description", "unknown")
            build = props.get("Build", {}).get("description", "unknown")
            print(f"OK (BIG-IP {version} build {build})")
            return
        print("OK")
    except requests.RequestException as e:
        print("FAILED")
        print(f"  ERROR: Cannot connect to BIG-IP at {host}: {e}", file=sys.stderr)
        print("  Check management IP, credentials, and network.", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI and main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="TLS Load Test with BIG-IP Metrics — Non-PQC vs PQC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s --bigip-host 10.1.1.4 --bigip-user admin --bigip-pass admin -k\n"
            "  %(prog)s --engine native --workers 16 --duration 120 --csv results.csv\n"
            "  %(prog)s --engine curl --workers 4 -k   # legacy curl mode\n"
            "  %(prog)s --non-pqc-vip 10.1.10.20 --pqc-vip 10.1.10.30 -k\n"
        ),
    )

    # Target VIPs
    parser.add_argument("--non-pqc-vip", default="10.1.10.20",
                        help="VIP with standard clientssl profile (default: 10.1.10.20)")
    parser.add_argument("--pqc-vip", default="10.1.10.30",
                        help="VIP with PQC-enabled clientssl profile (default: 10.1.10.30)")
    parser.add_argument("--non-pqc-groups", default="X25519",
                        help="key exchange group for non-PQC VIP (default: X25519)")
    parser.add_argument("--pqc-groups", default="X25519MLKEM768",
                        help="key exchange group for PQC VIP (default: X25519MLKEM768)")

    # BIG-IP credentials
    parser.add_argument("--bigip-host", required=True,
                        help="BIG-IP management IP (e.g., 10.1.1.4)")
    parser.add_argument("--bigip-user", required=True,
                        help="BIG-IP admin username")
    parser.add_argument("--bigip-pass", default="",
                        help="BIG-IP admin password (or set BIGIP_PASSWORD env var)")

    # Load test parameters
    parser.add_argument("--duration", type=int, default=300,
                        help="test duration per scenario in seconds (default: 300)")
    parser.add_argument("--workers", type=int, default=4,
                        help="concurrent worker processes (default: 4)")
    parser.add_argument("--poll-interval", type=int, default=5,
                        help="BIG-IP metrics polling interval in seconds (default: 5)")

    # TLS options
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="skip TLS certificate verification")
    parser.add_argument("--sni", default="",
                        help="SNI hostname for cert validation when targeting IPs")
    parser.add_argument("--timeout", type=int, default=10,
                        help="connection timeout in seconds (default: 10)")

    # Output
    parser.add_argument("--csv", metavar="FILE",
                        help="export results to CSV (creates _summary.csv and _metrics.csv)")

    # Engine selection
    parser.add_argument("--engine", choices=["auto", "native", "curl"], default="auto",
                        help="handshake engine: native (fast, Python ssl), "
                             "curl (subprocess), auto (try native, fall back to curl). "
                             "Default: auto")
    parser.add_argument("--batch-size", type=int, default=1,
                        help="concurrent connections per worker (threaded). "
                             "Effective concurrency = workers × batch-size. "
                             "Native engine only. (default: 1)")

    args = parser.parse_args()

    # Resolve BIG-IP password: CLI arg > env var > error
    bigip_pass = args.bigip_pass
    if not bigip_pass:
        bigip_pass = os.environ.get("BIGIP_PASSWORD", "")
    if not bigip_pass:
        parser.error("BIG-IP password required: use --bigip-pass or set BIGIP_PASSWORD env var")

    # Resolve engine: auto → probe native support, pick best option
    engine = args.engine
    if engine == "auto":
        test_groups = list({args.non_pqc_groups, args.pqc_groups})
        supported, details = probe_native_support(test_groups)
        if supported:
            engine = "native"
            print(f"Engine: auto → native ({details})")
        else:
            engine = "curl"
            print(f"Engine: auto → curl ({details})")
    else:
        print(f"Engine: {engine}")

    # If native was explicitly requested, verify groups are supported
    if args.engine == "native":
        test_groups = list({args.non_pqc_groups, args.pqc_groups})
        supported, details = probe_native_support(test_groups)
        if not supported:
            print(f"ERROR: {details}", file=sys.stderr)
            print(f"  Python ssl is linked against: {ssl.OPENSSL_VERSION}",
                  file=sys.stderr)
            print("  Use --engine curl or build Python against OpenSSL 3.5+.",
                  file=sys.stderr)
            sys.exit(1)

    # Resolve batch size
    batch_size = args.batch_size
    if batch_size < 1:
        batch_size = 1
    if engine == "curl" and batch_size > 1:
        print("WARNING: --batch-size > 1 only works with native engine, ignoring.")
        batch_size = 1
    effective_conns = args.workers * batch_size

    # Banner
    print(f"\nTLS Load Test — Non-PQC vs PQC Comparison")
    batch_info = f" × {batch_size} batch" if batch_size > 1 else ""
    print(f"Duration: {args.duration}s per scenario | Workers: {args.workers}"
          f"{batch_info} | Concurrency: {effective_conns} | Engine: {engine}")
    print(f"Non-PQC VIP: {args.non_pqc_vip} ({args.non_pqc_groups})")
    print(f"PQC VIP:     {args.pqc_vip} ({args.pqc_groups})")
    print()
    check_prerequisites(engine)
    verify_bigip_connection(args.bigip_host, args.bigip_user, bigip_pass)

    # Define scenarios
    scenarios = [
        LoadTestScenario(
            label="Non-PQC (ECDH only)",
            target=args.non_pqc_vip,
            tls_version="1.3",
            groups=args.non_pqc_groups,
        ),
        LoadTestScenario(
            label="PQC (ECDH + ML-KEM hybrid)",
            target=args.pqc_vip,
            tls_version="1.3",
            groups=args.pqc_groups,
        ),
    ]

    # Run scenarios sequentially for isolated BIG-IP measurements
    reports = []
    for i, scenario in enumerate(scenarios):
        report = run_load_scenario(
            scenario=scenario,
            workers=args.workers,
            duration=args.duration,
            insecure=args.insecure,
            sni=args.sni,
            timeout=args.timeout,
            bigip_host=args.bigip_host,
            bigip_user=args.bigip_user,
            bigip_pass=bigip_pass,
            poll_interval=args.poll_interval,
            engine=engine,
            batch_size=batch_size,
        )
        if report:
            reports.append(report)

        # Pause between scenarios to let BIG-IP stabilize
        if i < len(scenarios) - 1 and report:
            print(f"\n  Pausing 30s between scenarios to stabilize BIG-IP baseline...")
            time.sleep(30)

    if reports:
        print_comparison_report(reports)

        if args.csv:
            print("\nExporting CSV:")
            export_csv(reports, args.csv)
    else:
        print("\nNo scenarios completed successfully.")


if __name__ == "__main__":
    main()
