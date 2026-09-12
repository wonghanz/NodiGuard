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

class NodiProxyHandler(BaseHTTPRequestHandler):
    dlp = NodiGuardDLP()
    anonymizer = TokenAnonymizer()
    optimizer = SystemOptimizer()

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
        upstream_key = os.environ.get("UPSTREAM_API_KEY", "")

        # Fallback to Authorization header passed from IDE if UPSTREAM_API_KEY not in env
        auth_header = self.headers.get("Authorization", "")
        if not upstream_key and auth_header:
            upstream_key = auth_header.replace("Bearer ", "").strip()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {upstream_key}" if upstream_key else ""
        }

        try:
            # ZERO BLIND FOLLOW: Set allow_redirects=False to prevent prompt/token exfiltration on 30x hijacks
            resp = requests.post(
                f"{upstream_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=60,
                allow_redirects=False
            )

            # Detect and neutralize suspicious 30x redirect hijacking
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                redirect_target = resp.headers.get("Location", "unknown")
                self._send_json(502, {
                    "error": {
                        "message": f"[NODIGUARD HIJACK SHIELD]: Upstream returned HTTP {resp.status_code} redirecting to '{redirect_target}'. Request blocked to prevent unauthorized prompt/token exfiltration.",
                        "type": "security_violation",
                        "code": "upstream_redirect_blocked",
                        "target_location": redirect_target
                    }
                })
                return

            # Validate upstream content type: catch Cloudflare edge HTML error/redirect pages
            content_type = resp.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                self._send_json(502, {
                    "error": {
                        "message": f"[NODIGUARD GATEWAY ERROR]: Upstream returned non-JSON response ('{content_type}'). Possible CDN edge error or unverified landing page.",
                        "type": "upstream_protocol_error",
                        "code": "non_json_upstream_response",
                        "status_code": resp.status_code
                    }
                })
                return

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
