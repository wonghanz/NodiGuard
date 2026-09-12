"""
NodiGuard CLI (Command Line Interface).
Provides user-facing terminal commands:
  nodiguard start     - Launches the local security reverse proxy
  nodiguard scan      - Scans files/directories for credentials and MVP flaws
  nodiguard optimize  - Runs instant PC Manager-style RAM/VRAM cleanup
  nodiguard status    - Displays current protection and system resource status
"""

import os
import sys
import argparse
from typing import List

from . import __version__
from .proxy import NodiProxy
from .dlp import NodiGuardDLP
from .optimizer import SystemOptimizer

def command_start(args):
    """Starts the local security proxy."""
    host = args.host or os.environ.get("NODIGUARD_HOST", "127.0.0.1")
    port = args.port or int(os.environ.get("NODIGUARD_PORT", "8080"))

    if args.upstream:
        os.environ["UPSTREAM_BASE_URL"] = args.upstream
    if args.fallback:
        os.environ["FALLBACK_BASE_URL"] = args.fallback
    if args.api_key:
        os.environ["UPSTREAM_API_KEY"] = args.api_key

    print("=" * 60)
    print(f"  NodiGuard Community Edition v{__version__}")
    print("  Zero-Trust Local AI Security Proxy & System Optimizer")
    print("=" * 60)
    print(f"  > Listening on    : http://{host}:{port}")
    print(f"  > Upstream URL    : {os.environ.get('UPSTREAM_BASE_URL', 'https://api.openai.com/v1')}")
    print(f"  > Memory Compactor: Windows Native (EmptyWorkingSet)")
    print(f"  > Pre-Flight DLP  : 40+ credential formats & Shannon entropy active")
    print("-" * 60)
    print("  Cursor / VS Code Setup:")
    print(f"  - Override Base URL: http://{host}:{port}/v1")
    print("  - API Key: sk-local (or your preferred token)")
    print("=" * 60)

    proxy = NodiProxy(host=host, port=port)
    proxy.start(blocking=True)

def command_scan(args):
    """Scans a file or directory for credential leaks and insecure MVP patterns."""
    path = args.path
    if not os.path.exists(path):
        print(f"[!] Error: Target path does not exist: {path}")
        sys.exit(1)

    dlp = NodiGuardDLP()
    files_to_scan: List[str] = []

    if os.path.isfile(path):
        files_to_scan.append(path)
    else:
        for root, _, files in os.walk(path):
            parts = [p for p in root.split(os.sep) if p and p not in (".", "..")]
            if any(p.startswith(".") or p in ("node_modules", "venv", "__pycache__", "build", "dist") for p in parts):
                continue
            for f in files:
                if f.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".json", ".yaml", ".yml", ".md")):
                    files_to_scan.append(os.path.join(root, f))

    print(f"[*] Scanning {len(files_to_scan)} files with NodiGuard DLP...")
    total_findings = 0

    for fpath in files_to_scan:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            res = dlp.inspect_and_harden_code(content)
            if not res.is_safe:
                print(f"\n[!] Vulnerability found in {fpath}:")
                for finding in res.findings:
                    total_findings += 1
                    print(f"    [{finding.severity}] {finding.category}: {finding.description}")
                    if finding.matched_snippet:
                        print(f"       Snippet: {finding.matched_snippet}")
                    if finding.remediation:
                        print(f"       Fix: {finding.remediation}")
        except Exception as e:
            pass

    print("-" * 60)
    if total_findings == 0:
        print("[+] Scan complete: Zero credential leaks or insecure MVP patterns detected! Clean.")
    else:
        print(f"[!] Scan complete: {total_findings} security issues identified. Hardening recommended.")
        sys.exit(1 if args.strict else 0)

def command_optimize(args):
    """Executes instant RAM compaction and local GPU VRAM flush."""
    print("[*] Initiating NodiGuard System Performance Compaction...")
    optimizer = SystemOptimizer()
    ram_res = optimizer.optimize_ram()
    print(f"  [RAM] Process RSS Before : {ram_res['mem_before_mb']} MB")
    print(f"  [RAM] Process RSS After  : {ram_res['mem_after_mb']} MB")
    print(f"  [RAM] Memory Released    : {ram_res['released_ram_mb']} MB")
    print(f"  [RAM] Windows Native API : {'EmptyWorkingSet Invoked' if ram_res['windows_native_flush'] else 'GC Only'}")

    model_target = args.model or "nodi-go"
    vram_res = optimizer.purge_gpu_vram(model_name=model_target)
    print(f"  [GPU] VRAM Purge Status  : {vram_res['status']} ({vram_res.get('message', vram_res.get('reason'))})")

    cache_res = optimizer.clean_temp_cache()
    print(f"  [CACHE] Temp Files Purged: {cache_res['cleaned_files']} files ({cache_res['cleaned_kb']} KB)")
    print("[+] System optimization finished successfully.")

def command_status(args):
    """Displays NodiGuard status and health."""
    print("=" * 60)
    print(f"  NodiGuard Community Edition v{__version__} Status")
    print("=" * 60)
    try:
        import psutil
        mem = psutil.virtual_memory()
        print(f"  Total System RAM : {round(mem.total / (1024**3), 2)} GB")
        print(f"  Available RAM    : {round(mem.available / (1024**3), 2)} GB ({100 - mem.percent}% free)")
        print(f"  CPU Utilization  : {psutil.cpu_percent(interval=0.5)}%")
    except Exception:
        print("  System metrics   : psutil not available")

    # Check local proxy health if running
    host = os.environ.get("NODIGUARD_HOST", "127.0.0.1")
    port = os.environ.get("NODIGUARD_PORT", "8080")
    import requests
    try:
        r = requests.get(f"http://{host}:{port}/health", timeout=1)
        if r.status_code == 200:
            print(f"  Local Proxy Status: RUNNING on http://{host}:{port}")
        else:
            print(f"  Local Proxy Status: Responded with HTTP {r.status_code}")
    except Exception:
        print(f"  Local Proxy Status: STOPPED (run 'nodiguard start' to activate)")

def command_cf_audit(args):
    """Probes and diagnoses Cloudflare edge health, 301 redirects, and 502 errors."""
    from .cf_sentinel import CloudflareSentinel
    sentinel = CloudflareSentinel(args.url)
    report = sentinel.probe_edge()
    sentinel.print_report(report)

def main():
    parser = argparse.ArgumentParser(
        prog="nodiguard",
        description="NodiGuard Community Edition: Zero-Trust Local AI Security Proxy & System Optimizer"
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Start
    start_parser = subparsers.add_parser("start", help="Start the local AI security proxy daemon")
    start_parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    start_parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    start_parser.add_argument("--upstream", help="Upstream LLM Base URL (default: https://api.openai.com/v1)")
    start_parser.add_argument("--fallback", help="Fallback Base URL on upstream failure (e.g. http://192.168.0.188:8090)")
    start_parser.add_argument("--api-key", help="Upstream API key")

    # Scan
    scan_parser = subparsers.add_parser("scan", help="Scan code files for credential leaks and MVP flaws")
    scan_parser.add_argument("path", nargs="?", default=".", help="File or directory path to scan (default: .)")
    scan_parser.add_argument("--strict", action="store_true", help="Exit with non-zero code if vulnerabilities found")

    # Optimize
    opt_parser = subparsers.add_parser("optimize", help="Run instant Windows RAM compaction and VRAM purge")
    opt_parser.add_argument("--model", default="nodi-go", help="Local Ollama model name to unload from VRAM")

    # Status
    subparsers.add_parser("status", help="Show system memory and local proxy status")

    # Cloudflare Edge Audit
    cf_parser = subparsers.add_parser("cf-audit", help="Probe and diagnose Cloudflare edge health, 301 redirects, and 502 errors")
    cf_parser.add_argument("--url", default="https://ai.iotservices.my", help="Cloudflare edge URL to audit (default: https://ai.iotservices.my)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "start":
        command_start(args)
    elif args.command == "scan":
        command_scan(args)
    elif args.command == "optimize":
        command_optimize(args)
    elif args.command == "status":
        command_status(args)
    elif args.command == "cf-audit":
        command_cf_audit(args)

if __name__ == "__main__":
    main()
