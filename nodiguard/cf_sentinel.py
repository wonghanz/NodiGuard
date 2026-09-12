"""
NodiGuard Cloudflare Sentinel and Edge Diagnostics.
Diagnoses Cloudflare edge routing, detects 301 redirect hijacks, 502 Bad Gateways,
and provides automated audit and remediation advice directly from local machine.
"""

import os
import sys
import json
import requests
from typing import Dict, Any, Optional

class CloudflareSentinel:
    def __init__(self, target_url: str = "https://ai.iotservices.my"):
        self.target_url = target_url.rstrip("/")

    def probe_edge(self) -> Dict[str, Any]:
        result = {
            "url": self.target_url,
            "status_code": None,
            "is_cloudflare": False,
            "cf_ray": None,
            "redirect_location": None,
            "content_type": None,
            "diagnosis": "UNKNOWN",
            "action_required": []
        }

        try:
            resp = requests.get(
                self.target_url,
                timeout=10,
                allow_redirects=False,
                headers={"User-Agent": "NodiGuard-Sentinel/0.1.0"}
            )
            result["status_code"] = resp.status_code
            result["content_type"] = resp.headers.get("Content-Type", "")
            result["cf_ray"] = resp.headers.get("CF-RAY")
            result["is_cloudflare"] = "cloudflare" in resp.headers.get("Server", "").lower()

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                result["redirect_location"] = location
                result["diagnosis"] = "EDGE_REDIRECT_HIJACK_DETECTED"
                result["action_required"].append(
                    f"CRITICAL: Edge returned 301 redirect to '{location}'. "
                    "Check Cloudflare Dashboard -> Rules -> Page Rules or Redirect Rules for wildcard '*iotservices.my/*'."
                )
            elif resp.status_code == 502:
                result["diagnosis"] = "ORIGIN_UNREACHABLE_OR_SSL_MISMATCH"
                result["action_required"].append(
                    "Cloudflare 502 Bad Gateway: Cloudflare edge cannot establish a valid TCP/TLS handshake with your Origin server.\n"
                    "  Causes:\n"
                    "  1. Cloudflare SSL/TLS mode is set to 'Full (Strict)', but your Origin IP has no valid SSL certificate.\n"
                    "     -> Fix: In Cloudflare Dashboard -> SSL/TLS, set encryption mode to 'Flexible'.\n"
                    "  2. Origin IP port 80/443 is not exposed/forwarded to the internet.\n"
                    "     -> Fix: Use 'cloudflared tunnel' to establish an outbound-only encrypted tunnel without port-forwarding."
                )
            elif resp.status_code in (200, 404):
                if "application/json" in result["content_type"]:
                    result["diagnosis"] = "HEALTHY_AI_GATEWAY"
                else:
                    result["diagnosis"] = "EDGE_ACTIVE_BUT_HTML_RETURNED"

        except Exception as e:
            result["diagnosis"] = f"CONNECTION_FAILED: {str(e)}"

        return result

    def print_report(self, res: Dict[str, Any]):
        print("=" * 65)
        print("  NodiGuard Cloudflare Edge Sentinel - Local Diagnostic Report")
        print("=" * 65)
        print(f"  Target Edge URL : {res['url']}")
        print(f"  HTTP Status Code: {res['status_code']}")
        print(f"  Cloudflare Edge : {'YES (Ray: ' + str(res['cf_ray']) + ')' if res['is_cloudflare'] else 'NO'}")
        print(f"  Diagnosis       : {res['diagnosis']}")
        if res.get("redirect_location"):
            print(f"  Redirect Target : {res['redirect_location']}")
        print("-" * 65)
        if res["action_required"]:
            print("  [!] RECOMMENDED ACTIONS:")
            for act in res["action_required"]:
                print(f"  - {act}")
        else:
            print("  [+] Edge status normal.")
        print("=" * 65)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://ai.iotservices.my"
    sentinel = CloudflareSentinel(target)
    report = sentinel.probe_edge()
    sentinel.print_report(report)
