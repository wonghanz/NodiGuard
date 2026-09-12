"""
NodiGuard Local Reverse Proxy Engine (127.0.0.1:8080).
Acts as a zero-trust intermediary between local developer tools (Cursor, VS Code, Aider)
and upstream LLM endpoints (OpenAI, Claude, DeepSeek, or local Ollama).
Interception Pipeline:
1. Pre-Flight DLP & Adversarial Check ->
2. Mathematical Anonymization (Tokens stored only in local RAM) ->
3. Upstream Forwarding ->
4. Response De-anonymization & Code Hardening ->
5. Autonomous RAM/VRAM Garbage Collection.
"""

import os
import json
import time
import threading
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional

from .dlp import NodiGuardDLP
from .anonymizer import TokenAnonymizer
from .optimizer import SystemOptimizer
from .waf_enforcer import CloudflareWAFEnforcer

class NodiProxyHandler(BaseHTTPRequestHandler):
    dlp = NodiGuardDLP()
    anonymizer = TokenAnonymizer()
    optimizer = SystemOptimizer()
    waf = CloudflareWAFEnforcer()

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._send_json(200, {
                "service": "NodiGuard Local Security Proxy",
                "version": "0.1.0",
                "status": "healthy",
                "mode": "community-standalone",
                "features": ["Pre-Flight DLP", "Client Tokenizer", "RAM Compaction", "GPU Purge"]
            })
        elif self.path == "/v1/models":
            # Provide standard model catalog for IDEs like Cursor / Continue
            self._send_json(200, {
                "object": "list",
                "data": [
                    {"id": "nodiguard-shield", "object": "model", "owned_by": "local-sentinel"},
                    {"id": "gpt-4o", "object": "model", "owned_by": "upstream"},
                    {"id": "claude-3-7-sonnet", "object": "model", "owned_by": "upstream"},
                ]
            })
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        client_ip = self.headers.get("CF-Connecting-IP") or self.headers.get("X-Forwarded-For") or (self.client_address[0] if self.client_address else "127.0.0.1")

        # 0. Check if client IP is quarantined
        if self.waf.is_banned(client_ip):
            self._send_json(403, {
                "error": {
                    "message": "[NODIGUARD WAF]: Access Denied. Your IP has been permanently blacklisted for security violations.",
                    "type": "access_denied",
                    "code": "ip_blacklisted"
                }
            })
            return

        # 1. Handle Mobile / Web App Tamper Alert (RASP Threat Signal)
        if self.path == "/api/security/tamper-alert":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            try:
                alert_data = json.loads(post_data.decode("utf-8"))
            except Exception:
                alert_data = {}
            reason = alert_data.get("reason", "Mobile App Decompilation / Frida Hook Detected")
            self.waf.ban_ip(client_ip, reason=reason)
            masked_ip = self.anonymizer.mask_ip_for_logs(client_ip)
            print(f"[!] [NODIGUARD RASP ALERT] Decompilation/Tamper detected from {masked_ip}: {reason}. Banning IP...")
            self._send_json(200, {"status": "quarantined", "action": "ip_banned"})
            return

        # 2. Check for Honey-Token Reconnaissance Traps
        auth_header = self.headers.get("Authorization", "")
        if "honey" in auth_header.lower() or "canary" in auth_header.lower():
            # 100% Attacker Reconnaissance Triggered
            self.waf.ban_ip(client_ip, reason="Honey-Token Trap Triggered by Reverse Engineering")
            masked_ip = self.anonymizer.mask_ip_for_logs(client_ip)
            print(f"[!] [NODIGUARD HONEYPOT] Attacker {masked_ip} triggered Honey-Token trap! Dispatching Cloudflare ban...")
            self._send_json(403, {
                "error": {
                    "message": "[SECURITY ALERT] Unauthorized Canary Token detected. Your IP has been permanently blacklisted.",
                    "type": "security_violation",
                    "code": "honeytoken_triggered"
                }
            })
            return

        if not self.path.startswith("/v1/chat/completions"):
            self._send_json(404, {"error": "Endpoint not supported. Use /v1/chat/completions"})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            payload = json.loads(post_data.decode("utf-8"))
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON payload: {str(e)}"})
            return

        messages = payload.get("messages", [])
        if not messages:
            self._send_json(400, {"error": "Missing 'messages' array in request body"})
            return

        # 1. Pre-Flight DLP & Anonymization on last user message
        last_msg = messages[-1]
        raw_content = last_msg.get("content", "")
        if isinstance(raw_content, str) and raw_content:
            # DLP Inspection
            dlp_res = self.dlp.inspect_prompt(raw_content)
            if not dlp_res.is_safe:
                # If critical injection or leak found
                for finding in dlp_res.findings:
                    if finding.category == "ADVERSARIAL_INJECTION":
                        self._send_json(403, {
                            "error": {
                                "message": f"[NODIGUARD BLOCKED]: {finding.description}",
                                "type": "security_violation",
                                "code": "prompt_injection_detected"
                            }
                        })
                        return

            # Client Tokenization (Mapping kept in local RAM)
            anonymized_content, redaction_map = self.anonymizer.anonymize(dlp_res.sanitized_text)
            last_msg["content"] = anonymized_content
            payload["messages"][-1] = last_msg
        else:
            redaction_map = {}

        # 2. Forward to Upstream LLM Gateway
        upstream_url = os.environ.get("UPSTREAM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        fallback_url = os.environ.get("FALLBACK_BASE_URL", "").rstrip("/")
        upstream_key = os.environ.get("UPSTREAM_API_KEY", "")

        # Fallback to Authorization header passed from IDE if UPSTREAM_API_KEY not in env
        auth_header = self.headers.get("Authorization", "")
        if not upstream_key and auth_header:
            upstream_key = auth_header.replace("Bearer ", "").strip()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {upstream_key}" if upstream_key else ""
        }

        def _forward_call(target_base: str):
            r = requests.post(
                f"{target_base}/chat/completions",
                json=payload,
                headers=headers,
                timeout=60,
                allow_redirects=False
            )
            # Detect suspicious redirect
            if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "unknown")
                return False, r, f"HTTP {r.status_code} redirecting to '{loc}'", "upstream_redirect_blocked", loc
            # Detect CDN edge error or gateway failure
            if r.status_code in (502, 503, 504):
                return False, r, f"Edge Error HTTP {r.status_code}", "edge_gateway_error", None
            # Validate JSON content type
            ct = r.headers.get("Content-Type", "")
            if "application/json" not in ct:
                return False, r, f"Non-JSON Content-Type ('{ct}')", "non_json_upstream_response", None
            return True, r, "Success", "ok", None

        # 1. Attempt Primary Upstream
        resp = None
        success, resp, reason, err_code, loc = False, None, "", "", None

        try:
            success, resp, reason, err_code, loc = _forward_call(upstream_url)
        except Exception as e:
            reason = str(e)
            err_code = "upstream_connection_failed"

        # 2. Seamless Failover to Fallback Node if primary failed
        if not success and fallback_url:
            masked_fb = self.anonymizer.mask_ip_for_logs(fallback_url)
            print(f"[*] [NODIGUARD FAILOVER] Primary ({upstream_url}) failed: {reason}. Failing over to {masked_fb}...")
            try:
                fb_success, fb_resp, fb_reason, fb_code, _ = _forward_call(fallback_url)
                if fb_success:
                    resp = fb_resp
                    success = True
            except Exception as e:
                print(f"[!] [NODIGUARD FAILOVER] Fallback failed: {e}")

        # 3. If still unsuccessful, return structured security / gateway error
        if not success:
            err_msg = f"[NODIGUARD GATEWAY ERROR]: Upstream failed ({reason})."
            if loc:
                err_msg = f"[NODIGUARD HIJACK SHIELD]: Upstream returned HTTP redirect to '{loc}'. Request blocked to prevent unauthorized prompt/token exfiltration."
            self._send_json(502, {
                "error": {
                    "message": err_msg,
                    "type": "security_violation" if loc else "upstream_gateway_error",
                    "code": err_code,
                    "target_location": loc
                }
            })
            return

        try:
            resp_data = resp.json()
        except Exception as e:
            self._send_json(502, {"error": f"Failed to reach upstream LLM: {str(e)}"})
            return

        # 3. Post-Flight De-anonymization & Code Hardening
        if resp.status_code == 200 and "choices" in resp_data:
            for choice in resp_data.get("choices", []):
                msg = choice.get("message", {})
                content = msg.get("content", "")
                if content:
                    # De-anonymize back to original local values
                    restored = self.anonymizer.de_anonymize(content, redaction_map)
                    # Anti-Vibe-Coding hardening
                    hardened_res = self.dlp.inspect_and_harden_code(restored)
                    msg["content"] = hardened_res.sanitized_text
                    choice["message"] = msg

        # Send response back to IDE/Client
        self._send_json(resp.status_code, resp_data)

        # 4. Trigger Autonomous Post-Turn Memory & VRAM Optimization in Background
        def _post_cleanup():
            time.sleep(0.5)
            self.optimizer.optimize_ram()
            if os.environ.get("AUTO_PURGE_VRAM", "true").lower() == "true":
                self.optimizer.purge_gpu_vram()

        threading.Thread(target=_post_cleanup, daemon=True).start()

    def log_message(self, format, *args):
        # Quiet standard HTTP access logs unless debug mode is active
        if os.environ.get("NODIGUARD_DEBUG", "0") == "1":
            super().log_message(format, *args)

class NodiProxy:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = True):
        self.server = HTTPServer((self.host, self.port), NodiProxyHandler)
        print(f"[*] NodiGuard Local Proxy listening on http://{self.host}:{self.port}")
        print(f"[*] Compatible with OpenAI /v1 endpoints for Cursor, VS Code, and CLI.")
        if blocking:
            try:
                self.server.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("[*] NodiGuard Local Proxy stopped.")
