#!/usr/bin/env python3
"""
TLS Key Exchange Latency Benchmark
Compares ECDH (TLS 1.2 & 1.3) vs Post-Quantum (PQC) hybrid key exchanges.

Requirements:
  - curl built with OpenSSL 3.2+ for PQC cipher support
  - Network access to the target server

Usage:
  python3 tls_latency_bench.py -t 10.0.1.10 10.0.1.11        # multiple VIPs by IP
  python3 tls_latency_bench.py -t 10.0.1.10 --sni app.example.com  # IP + SNI hostname
  python3 tls_latency_bench.py -t 10.0.1.10 -k                # skip cert verification
  python3 tls_latency_bench.py -t cloudflare.com -n 50        # hostname, 50 iterations
  python3 tls_latency_bench.py --csv results.csv              # export to CSV
"""

import argparse
import json
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field


@dataclass
class TestCase:
    label: str
    tls_version: str       # "1.2" or "1.3"
    groups: str            # key exchange group(s) passed to --curves
    cipher: str = ""       # --ciphers (TLS 1.2 only)
    tls13_cipher: str = "" # --tls13-ciphers (TLS 1.3 override, optional)


@dataclass
class BenchResult:
    test: TestCase
    times_ms: list = field(default_factory=list)
    errors: int = 0

    @property
    def valid(self):
        return len(self.times_ms) > 0

    def stats(self):
        t = self.times_ms
        if not t:
            return {}
        s = sorted(t)
        return {
            "min": min(t),
            "avg": statistics.mean(t),
            "median": statistics.median(t),
            "p95": s[int(len(s) * 0.95)] if len(s) >= 20 else max(t),
            "max": max(t),
            "stddev": statistics.stdev(t) if len(t) > 1 else 0.0,
            "samples": len(t),
        }


# ---------------------------------------------------------------------------
# Test matrix
#
# ECDH baselines use well-known curves. PQC tests use hybrid names from
# OpenSSL 3.2+ (x25519_kyber768) and OpenSSL 3.5+ / standardised names
# (X25519MLKEM768, SecP256r1MLKEM768). Unsupported configs are detected
# automatically and reported as such.
# ---------------------------------------------------------------------------
TESTS = [
    # --- TLS 1.2: ECDHE baselines ---
    TestCase(
        label="ECDHE-P256 (TLS 1.2)",
        tls_version="1.2",
        groups="P-256",
        cipher="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
    ),
    TestCase(
        label="ECDHE-P384 (TLS 1.2)",
        tls_version="1.2",
        groups="P-384",
        cipher="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
    ),
    # --- TLS 1.3: ECDH baselines ---
    TestCase(
        label="X25519 (TLS 1.3)",
        tls_version="1.3",
        groups="X25519",
    ),
    TestCase(
        label="P-256 (TLS 1.3)",
        tls_version="1.3",
        groups="P-256",
    ),
    TestCase(
        label="P-384 (TLS 1.3)",
        tls_version="1.3",
        groups="P-384",
    ),
    # --- TLS 1.3: PQC / Hybrid key exchanges ---
    TestCase(
        label="X25519+MLKEM768 hybrid (TLS 1.3)",
        tls_version="1.3",
        groups="X25519MLKEM768",
    ),
    TestCase(
        label="SecP256r1+MLKEM768 hybrid (TLS 1.3)",
        tls_version="1.3",
        groups="SecP256r1MLKEM768",
    ),
    TestCase(
        label="X25519+Kyber768 draft hybrid (TLS 1.3)",
        tls_version="1.3",
        groups="x25519_kyber768",
    ),
]


# curl -w format to extract timing data
CURL_WRITE_OUT = json.dumps({
    "time_namelookup": "%{time_namelookup}",
    "time_connect": "%{time_connect}",
    "time_appconnect": "%{time_appconnect}",
})


def check_prerequisites():
    """Print curl and OpenSSL versions for reference."""
    try:
        r = subprocess.run(["curl", "--version"], capture_output=True, text=True)
        first_line = r.stdout.splitlines()[0] if r.stdout else "curl: unknown version"
        print(f"  {first_line}")
        if "OpenSSL" not in r.stdout and "BoringSSL" not in r.stdout and "LibreSSL" not in r.stdout:
            print("  WARNING: curl may not be built with OpenSSL — PQC tests will likely fail.")
    except FileNotFoundError:
        print("ERROR: curl not found.", file=sys.stderr)
        sys.exit(1)

    try:
        r = subprocess.run(["openssl", "version"], capture_output=True, text=True)
        print(f"  {r.stdout.strip()}")
    except FileNotFoundError:
        print("  openssl CLI not found (optional)")


def run_single(target: str, test: TestCase, timeout: int = 10,
               insecure: bool = False, sni: str = ""):
    """Execute one TLS handshake and return handshake duration in ms, or None on failure."""
    cmd = [
        "curl", "-so", "/dev/null",
        "-w", CURL_WRITE_OUT,
        "--connect-timeout", str(timeout),
    ]

    if insecure:
        cmd.append("-k")

    # When connecting to an IP with an SNI hostname, use --resolve to map
    # the hostname to the IP so curl sends the correct SNI and validates
    # the cert against the hostname rather than the raw IP.
    if sni:
        port = 443
        cmd += ["--resolve", f"{sni}:{port}:{target}"]
        url_host = sni
    else:
        url_host = target

    if test.tls_version == "1.2":
        cmd += ["--tlsv1.2", "--tls-max", "1.2"]
    else:
        cmd += ["--tlsv1.3", "--tls-max", "1.3"]

    if test.cipher:
        cmd += ["--ciphers", test.cipher]
    if test.tls13_cipher:
        cmd += ["--tls13-ciphers", test.tls13_cipher]
    if test.groups:
        cmd += ["--curves", test.groups]

    cmd.append(f"https://{url_host}/")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        # curl may exit non-zero if the HTTP request fails after the TLS
        # handshake (e.g. connection reset by peer, empty reply).  The
        # timing data is still written to stdout, so we attempt to parse
        # it regardless of the exit code.  We only bail out if the JSON
        # is missing or the handshake times are zero (true TLS failure).
        data = json.loads(r.stdout)
        tcp_connect = float(data["time_connect"])
        tls_done = float(data["time_appconnect"])
        if tls_done <= 0 or tcp_connect <= 0:
            return None
        return (tls_done - tcp_connect) * 1000  # seconds -> ms
    except (json.JSONDecodeError, KeyError, ValueError, subprocess.TimeoutExpired):
        return None


def run_bench(target: str, iterations: int, warmup: int, timeout: int,
              insecure: bool = False, sni: str = ""):
    """Run the full benchmark suite against a single target and return results."""
    results = []
    total = len(TESTS)

    for idx, test in enumerate(TESTS, 1):
        print(f"\n[{idx}/{total}] {test.label}")
        result = BenchResult(test=test)

        # Warmup: prime DNS cache, detect unsupported configs early
        supported = False
        for _ in range(warmup):
            if run_single(target, test, timeout, insecure, sni) is not None:
                supported = True

        if not supported:
            # All warmup attempts failed — likely unsupported
            # Try one more to be sure
            if run_single(target, test, timeout, insecure, sni) is None:
                result.errors = iterations
                print(f"  SKIPPED — unsupported by curl/OpenSSL or server")
                results.append(result)
                continue

        # Measured iterations
        for i in range(iterations):
            t = run_single(target, test, timeout, insecure, sni)
            if t is not None:
                result.times_ms.append(t)
            else:
                result.errors += 1

            if (i + 1) % 10 == 0 or i == iterations - 1:
                ok = len(result.times_ms)
                print(f"  {i + 1}/{iterations}  ({ok} ok, {result.errors} err)", end="\r")

        if result.valid:
            s = result.stats()
            print(
                f"  done — avg={s['avg']:.2f}ms  "
                f"median={s['median']:.2f}ms  "
                f"stddev={s['stddev']:.2f}ms       "
            )
        else:
            print(f"  FAILED — all {result.errors} attempts errored       ")

        results.append(result)
        time.sleep(0.1)

    return results


def print_table(target: str, results):
    """Print a formatted comparison table for a single target."""
    w = 92
    print("\n" + "=" * w)
    print(f"  Target: {target}")
    print("=" * w)
    print(
        f"{'Key Exchange':<40} "
        f"{'Min':>7} {'Avg':>7} {'Med':>7} {'P95':>7} {'Max':>7} "
        f"{'σ':>6}  {'Δ':>7}"
    )
    print("-" * w)

    baseline_avg = None
    for r in results:
        if not r.valid:
            print(f"{r.test.label:<40} {'— unsupported / unreachable —':>51}")
            continue

        s = r.stats()
        if baseline_avg is None:
            baseline_avg = s["avg"]
            delta_str = "  (base)"
        else:
            pct = ((s["avg"] - baseline_avg) / baseline_avg) * 100
            delta_str = f" ({pct:+.1f}%)"

        print(
            f"{r.test.label:<40} "
            f"{s['min']:>7.2f} {s['avg']:>7.2f} {s['median']:>7.2f} "
            f"{s['p95']:>7.2f} {s['max']:>7.2f} "
            f"{s['stddev']:>6.2f} {delta_str}"
        )

    print("=" * w)
    print("All times in milliseconds (TLS handshake only, excludes TCP connect).")
    print("Δ% is relative to the first successful test.\n")


def export_csv(all_results: dict, path: str):
    """Export raw results to CSV. all_results is {target: [BenchResult, ...]}."""
    with open(path, "w") as f:
        f.write(
            "target,label,tls_version,group,min_ms,avg_ms,median_ms,"
            "p95_ms,max_ms,stddev_ms,samples,errors\n"
        )
        for target, results in all_results.items():
            for r in results:
                s = r.stats() if r.valid else {}
                f.write(
                    f'"{target}","{r.test.label}",{r.test.tls_version},{r.test.groups},'
                    f'{s.get("min", "")},{s.get("avg", "")},{s.get("median", "")},'
                    f'{s.get("p95", "")},{s.get("max", "")},{s.get("stddev", "")},'
                    f'{s.get("samples", 0)},{r.errors}\n'
                )
    print(f"Results exported to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="TLS Key Exchange Latency Benchmark — ECDH vs PQC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s -t 10.0.1.10 10.0.1.11 -k       # two VIPs, skip cert check\n"
            "  %(prog)s -t 10.0.1.10 --sni app.example.com  # IP with SNI hostname\n"
            "  %(prog)s -t cloudflare.com -n 50           # hostname, 50 iterations\n"
            "  %(prog)s --csv results.csv                  # export to CSV\n"
        ),
    )
    parser.add_argument(
        "-t", "--targets", nargs="+", default=["cloudflare.com"],
        metavar="IP_OR_HOST",
        help="one or more target IPs or hostnames (default: cloudflare.com)",
    )
    parser.add_argument(
        "--sni", default="",
        help="SNI hostname for cert validation when targeting IPs (uses --resolve under the hood)",
    )
    parser.add_argument(
        "-k", "--insecure", action="store_true",
        help="skip TLS certificate verification (useful for IP-only targets)",
    )
    parser.add_argument(
        "-n", "--iterations", type=int, default=30,
        help="measurement iterations per test case (default: 30)",
    )
    parser.add_argument(
        "--warmup", type=int, default=3,
        help="warmup iterations before measuring (default: 3)",
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--csv", metavar="FILE",
        help="export results to CSV file",
    )
    args = parser.parse_args()

    targets = args.targets
    print("TLS Key Exchange Latency Benchmark")
    print(f"Targets: {', '.join(targets)} | Iterations: {args.iterations} | Warmup: {args.warmup}")
    if args.sni:
        print(f"SNI: {args.sni}")
    if args.insecure:
        print("Certificate verification: DISABLED (-k)")
    print()
    check_prerequisites()

    all_results = {}
    for i, target in enumerate(targets):
        if len(targets) > 1:
            print(f"\n{'#' * 92}")
            print(f"# VIP {i + 1}/{len(targets)}: {target}")
            print(f"{'#' * 92}")

        results = run_bench(
            target, args.iterations, args.warmup, args.timeout,
            insecure=args.insecure, sni=args.sni,
        )
        print_table(target, results)
        all_results[target] = results

    if args.csv:
        export_csv(all_results, args.csv)


if __name__ == "__main__":
    main()
