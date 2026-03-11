#!/usr/bin/env python3
"""
TLS Load Test with BIG-IP Metrics Collection
Compares system resource impact of non-PQC vs PQC TLS handshakes under sustained load.

Generates concurrent TLS handshake load via multiprocessing workers, while polling
BIG-IP CPU, memory, TMM, and SSL stats via iControl REST API. Runs non-PQC and PQC
scenarios sequentially, then prints a side-by-side comparison report.

Requirements:
  - Python 3.10+
  - curl built with OpenSSL 3.2+ (3.5+ for ML-KEM PQC ciphers)
  - requests library: pip install requests
  - Network access to BIG-IP management interface and VIPs

Usage:
  python3 tls_load_test.py --bigip-host 10.1.1.4 --bigip-user admin --bigip-pass admin -k
  python3 tls_load_test.py --duration 120 --workers 8 --csv results.csv
"""

import argparse
import json
import multiprocessing
import os
import statistics
import subprocess
import sys
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
# Multiprocessing worker
# ---------------------------------------------------------------------------

def worker_loop(target, tls_version, groups, cipher, tls13_cipher,
                duration_seconds, insecure, sni, timeout, result_queue):
    """Worker process: continuously perform TLS handshakes for the given duration."""
    end_time = time.time() + duration_seconds
    results = []
    while time.time() < end_time:
        result = run_single_handshake(
            target=target,
            tls_version=tls_version,
            groups=groups,
            cipher=cipher,
            tls13_cipher=tls13_cipher,
            timeout=timeout,
            insecure=insecure,
            sni=sni,
        )
        results.append(result)
    result_queue.put(results)


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
    """Extract SSL connection count and TPS from /mgmt/tm/sys/performance/all-stats."""
    ssl_conns = 0
    ssl_tps = 0.0
    try:
        entries = perf_data.get("entries", {})
        for key, val in entries.items():
            nested = val.get("nestedStats", {}).get("entries", {})
            desc = nested.get("description", {})
            if isinstance(desc, dict):
                desc = desc.get("description", "")

            # Look for SSL-related performance counters
            key_lower = key.lower()
            if "ssl" in key_lower and "transaction" in key_lower:
                current = nested.get("current", {}).get("value", 0)
                ssl_tps = float(current)
            elif "ssl" in key_lower and ("conn" in key_lower or "concurrent" in key_lower):
                current = nested.get("current", {}).get("value", 0)
                ssl_conns = int(current)
    except (KeyError, TypeError, ValueError):
        pass
    return ssl_conns, ssl_tps


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
        ssl_conns, ssl_tps = _parse_ssl_stats(perf_data)

        return BigIPMetricSample(
            timestamp=time.time(),
            cpu_utilization=cpu_pct,
            memory_used_pct=mem_pct,
            tmm_cpu_pct=tmm_cpu,
            active_ssl_connections=ssl_conns,
            ssl_transactions_per_sec=ssl_tps,
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
                      bigip_host, bigip_user, bigip_pass, poll_interval):
    """Run a complete load test scenario: spawn workers + collect BIG-IP metrics."""
    w = 80
    print(f"\n{'=' * w}")
    print(f"  Scenario: {scenario.label}")
    print(f"  Target: {scenario.target} | Groups: {scenario.groups}")
    print(f"  Workers: {workers} | Duration: {duration}s")
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

    # Spawn worker processes
    result_queue = multiprocessing.Queue()
    processes = []
    start_time = time.time()

    for _ in range(workers):
        p = multiprocessing.Process(
            target=worker_loop,
            args=(scenario.target, scenario.tls_version, scenario.groups,
                  scenario.cipher, scenario.tls13_cipher, duration,
                  insecure, sni, timeout, result_queue),
        )
        processes.append(p)
        p.start()

    # Progress reporting while workers are running
    print(f"  Load test running...")
    while any(p.is_alive() for p in processes):
        elapsed = time.time() - start_time
        remaining = max(0, duration - elapsed)
        latest_cpu = f"{metrics_list[-1].cpu_utilization:.1f}" if metrics_list else "N/A"
        latest_tmm = f"{metrics_list[-1].tmm_cpu_pct:.1f}" if metrics_list else "N/A"
        print(f"\r  [{elapsed:>5.0f}s / {duration}s] "
              f"BIG-IP CPU: {latest_cpu}%  TMM: {latest_tmm}%  "
              f"Remaining: {remaining:.0f}s   ", end="", flush=True)
        time.sleep(5)

    # Wait for all workers to finish
    for p in processes:
        p.join(timeout=30)

    # Stop metrics collection
    stop_event.set()
    metrics_thread.join(timeout=5)

    elapsed = time.time() - start_time
    print(f"\r  Completed in {elapsed:.1f}s" + " " * 50)

    # Collect results from all workers
    all_results = []
    while not result_queue.empty():
        try:
            all_results.extend(result_queue.get_nowait())
        except Exception:
            break

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
            "bigip_tmm_cpu_avg,bigip_tmm_cpu_max\n"
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
                f'{r.bigip_tmm_cpu_avg:.1f},{r.bigip_tmm_cpu_max:.1f}\n'
            )
    print(f"  Summary:     {summary_path}")

    # Time-series metrics CSV
    metrics_path = f"{base}_metrics.csv"
    with open(metrics_path, "w") as f:
        f.write(
            "scenario,timestamp,elapsed_s,cpu_pct,memory_pct,"
            "tmm_cpu_pct,active_ssl_conns,ssl_tps\n"
        )
        for r in reports:
            start_ts = r.bigip_metrics[0].timestamp if r.bigip_metrics else 0
            for m in r.bigip_metrics:
                elapsed = m.timestamp - start_ts
                f.write(
                    f'"{r.scenario.label}",{m.timestamp:.3f},{elapsed:.1f},'
                    f'{m.cpu_utilization:.1f},{m.memory_used_pct:.1f},'
                    f'{m.tmm_cpu_pct:.1f},{m.active_ssl_connections},'
                    f'{m.ssl_transactions_per_sec:.1f}\n'
                )
    print(f"  Time-series: {metrics_path}")


# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

def check_prerequisites():
    """Print curl and OpenSSL versions."""
    try:
        r = subprocess.run(["curl", "--version"], capture_output=True, text=True)
        first_line = r.stdout.splitlines()[0] if r.stdout else "curl: unknown"
        print(f"  {first_line}")
    except FileNotFoundError:
        print("ERROR: curl not found.", file=sys.stderr)
        sys.exit(1)

    try:
        r = subprocess.run(["openssl", "version"], capture_output=True, text=True)
        print(f"  {r.stdout.strip()}")
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
            "  %(prog)s --duration 120 --workers 8 --csv results.csv\n"
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

    args = parser.parse_args()

    # Resolve BIG-IP password: CLI arg > env var > error
    bigip_pass = args.bigip_pass
    if not bigip_pass:
        bigip_pass = os.environ.get("BIGIP_PASSWORD", "")
    if not bigip_pass:
        parser.error("BIG-IP password required: use --bigip-pass or set BIGIP_PASSWORD env var")

    # Banner
    print("TLS Load Test — Non-PQC vs PQC Comparison")
    print(f"Duration: {args.duration}s per scenario | Workers: {args.workers} "
          f"| Poll interval: {args.poll_interval}s")
    print(f"Non-PQC VIP: {args.non_pqc_vip} ({args.non_pqc_groups})")
    print(f"PQC VIP:     {args.pqc_vip} ({args.pqc_groups})")
    print()
    check_prerequisites()
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
