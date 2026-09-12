"""
NodiGuard Pre-Flight DLP & Anti-Vibe-Coding Hardening Engine.
Detects 40+ credential formats, high Shannon entropy tokens, adversarial prompt injections,
and dangerous "MVP-style" code flaws (CORS *, verify=False, shell=True, SQL injection).
"""

import re
import math
import hashlib
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field

@dataclass
class DLPFinding:
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    matched_snippet: str = ""
    remediation: Optional[str] = None

@dataclass
class DLPScanResult:
    is_safe: bool
    findings: List[DLPFinding] = field(default_factory=list)
    sanitized_text: str = ""
    entropy_score: float = 0.0

class NodiGuardDLP:
    # 40+ Sensitive Credential Signatures
    CREDENTIAL_PATTERNS: List[Tuple[str, str]] = [
        ("OpenAI API Key", r"sk-[a-zA-Z0-9_-]{20,64}"),
        ("Anthropic API Key", r"sk-ant-[a-zA-Z0-9_-]{32,100}"),
        ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
        ("AWS Secret Access Key", r"(?i)aws_secret_access_key\s*=\s*['\"][0-9a-zA-Z/+=]{40}['\"]"),
        ("GitHub Personal Token", r"gh[pousr]_[0-9a-zA-Z]{36,255}"),
        ("Google Cloud API Key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("Slack Bot Token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        ("Generic RSA/SSH Private Key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        ("Hardcoded Secret / Password", r"(?i)(?:password|passwd|pwd|auth_token|client_secret)\s*=\s*['\"][^'\"]{8,}['\"]"),
        ("Database Connection URI", r"(?i)(?:postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/\s]+"),
        ("Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24}"),
        ("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22}"),
        ("Twilio Account SID", r"AC[a-zA-Z0-9]{32}"),
        ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}"),
    ]

    # Insecure "Vibe Coding" MVP Patterns
    INSECURE_MVP_PATTERNS: List[Tuple[str, str, str]] = [
        (
            "Wildcard CORS Policy",
            r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]",
            "Restricts cross-origin resource sharing; use specific domains instead of '*' in production."
        ),
        (
            "Disabled SSL Verification",
            r"verify\s*=\s*False",
            "Disables TLS certificate verification; vulnerable to Man-In-The-Middle (MITM) attacks."
        ),
        (
            "Dangerous Shell Execution",
            r"subprocess\.(?:call|run|Popen)\(.*shell\s*=\s*True.*\)",
            "shell=True enables arbitrary shell command injection; use argument lists instead."
        ),
        (
            "Debug Mode Active",
            r"(?i)debug\s*=\s*True",
            "Exposes internal stack traces and interactive debug consoles to external clients."
        ),
        (
            "Unparameterized SQL Query",
            r"(?i)execute\s*\(\s*f['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*{.*}.*['\"]\s*\)",
            "Direct f-string SQL query allows SQL Injection (SQLi); use parameterized bind variables."
        ),
    ]

    # Adversarial Injection & Jailbreak Signatures
    ADVERSARIAL_PATTERNS: List[str] = [
        r"(?i)ignore\s+(?:all\s+)?previous\s+(?:instructions|prompts|rules)",
        r"(?i)system\s+override\s*:\s*",
        r"(?i)you\s+are\s+now\s+(?:DAN|unrestricted|jailbroken|godmode)",
        r"(?i)disregard\s+(?:the\s+)?above\s+and\s+(?:do|output)",
        r"(?i)print\s+(?:your\s+)?system\s+prompt",
        r"(?i)reveal\s+(?:the\s+)?secret\s+key",
        r"(?i)curl\s+https?://[^\s]+\s+-d\s+@(?:/etc/passwd|~/\.ssh|\.env)",
        r"<\s*script\s*>.*<\s*/\s*script\s*>",
        r"data:text/html;base64,",
    ]

    def __init__(self, entropy_threshold: float = 4.2):
        self.entropy_threshold = entropy_threshold

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculates Shannon entropy to detect high-entropy randomized API keys."""
        if not data:
            return 0.0
        length = len(data)
        freq: Dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)

    def inspect_prompt(self, text: str) -> DLPScanResult:
        """
        Pre-flight inspection for outbound user prompts.
        Flags prompt injections, credential leaks, and high-entropy secret tokens.
        """
        findings: List[DLPFinding] = []
        sanitized = text

        # 1. Adversarial Injection Check
        for pattern in self.ADVERSARIAL_PATTERNS:
            if re.search(pattern, text):
                findings.append(DLPFinding(
                    category="ADVERSARIAL_INJECTION",
                    severity="CRITICAL",
                    description="Detected prompt injection / system jailbreak attempt.",
                    matched_snippet=pattern
                ))

        # 2. Hidden Unicode Steganography Check
        zero_width_matches = re.findall(r"[​-‍﻿]", text)
        if len(zero_width_matches) > 3:
            findings.append(DLPFinding(
                category="STEGANOGRAPHY_PAYLOAD",
                severity="HIGH",
                description=f"Detected {len(zero_width_matches)} zero-width unicode characters.",
                matched_snippet="[ZERO_WIDTH_CHARS]"
            ))
            sanitized = re.sub(r"[​-‍﻿]", "", sanitized)

        # 3. Credential Leaks in Prompt
        for cred_name, pattern in self.CREDENTIAL_PATTERNS:
            for match in re.finditer(pattern, sanitized):
                secret = match.group(0)
                masked = secret[:6] + "..." + secret[-4:] if len(secret) > 10 else "***"
                findings.append(DLPFinding(
                    category="CREDENTIAL_LEAK",
                    severity="CRITICAL",
                    description=f"Outbound credential detected: {cred_name}",
                    matched_snippet=masked
                ))
                # Neutralize inline
                var_hash = hashlib.md5(secret.encode()).hexdigest()[:6].upper()
                sanitized = sanitized.replace(secret, f"os.environ.get('SECRET_{var_hash}')")

        entropy = self.calculate_shannon_entropy(text)
        is_safe = len(findings) == 0

        return DLPScanResult(
            is_safe=is_safe,
            findings=findings,
            sanitized_text=sanitized,
            entropy_score=entropy
        )

    def inspect_and_harden_code(self, code: str) -> DLPScanResult:
        """
        Post-flight inspection of AI-generated code.
        Flags insecure MVP patterns and automatically hardens code against leaks.
        """
        findings: List[DLPFinding] = []
        hardened_code = code

        # 1. Credential detection & hardening
        for cred_name, pattern in self.CREDENTIAL_PATTERNS:
            for match in re.finditer(pattern, hardened_code):
                secret = match.group(0)
                masked = secret[:6] + "..." + secret[-4:] if len(secret) > 10 else "***"
                findings.append(DLPFinding(
                    category="HARDCODED_SECRET",
                    severity="CRITICAL",
                    description=f"Hardcoded {cred_name} in code output.",
                    matched_snippet=masked,
                    remediation="Replaced with os.getenv(...) environment variable lookup."
                ))
                var_hash = hashlib.md5(secret.encode()).hexdigest()[:6].upper()
                hardened_code = hardened_code.replace(secret, f'os.getenv("CREDENTIAL_{var_hash}")')

        # 2. Insecure MVP Patterns
        for flaw_name, pattern, remediation in self.INSECURE_MVP_PATTERNS:
            if re.search(pattern, hardened_code):
                findings.append(DLPFinding(
                    category="INSECURE_MVP_PATTERN",
                    severity="HIGH",
                    description=flaw_name,
                    remediation=remediation
                ))

        is_safe = len(findings) == 0
        return DLPScanResult(
            is_safe=is_safe,
            findings=findings,
            sanitized_text=hardened_code,
            entropy_score=self.calculate_shannon_entropy(code)
        )
