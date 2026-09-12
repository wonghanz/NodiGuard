"""
NodiGuard Token Anonymizer & Privacy Shield.
Performs client-side mathematical tokenization before sending prompts to external LLMs.
The real mapping table is stored strictly in ephemeral local memory (RAM) and NEVER leaves the machine.
"""

import re
from typing import Tuple, Dict

class TokenAnonymizer:
    # RFC 1918 Private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    PRIVATE_IP_PATTERN = r'\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b'
    
    # Standard email address pattern
    EMAIL_PATTERN = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    
    # Absolute file paths (Windows e.g. C:\Users\... or Unix e.g. /home/..., /Users/...)
    PATH_PATTERN = r'(?:[a-zA-Z]:\\[a-zA-Z0-9_\.\-\\]+|/(?:home|Users|var|etc)/[a-zA-Z0-9_\.\-/]+)'

    def __init__(self):
        pass

    def anonymize(self, raw_text: str) -> Tuple[str, Dict[str, str]]:
        """
        Tokenizes sensitive identifiers in user text.
        
        Returns:
            Tuple of (anonymized_text, local_mapping_dict)
            - anonymized_text: Safe to transmit over untrusted networks.
            - local_mapping_dict: Stored strictly in local RAM on client machine.
        """
        anonymized = raw_text
        mapping: Dict[str, str] = {}
        email_counter = 1
        ip_counter = 1
        path_counter = 1

        # 1. Tokenize Email addresses
        for match in list(re.finditer(self.EMAIL_PATTERN, anonymized)):
            val = match.group(0)
            if val not in mapping.values():
                placeholder = f"[MASKED_EMAIL_{email_counter}]"
                mapping[placeholder] = val
                anonymized = anonymized.replace(val, placeholder)
                email_counter += 1

        # 2. Tokenize Private IPv4 addresses
        for match in list(re.finditer(self.PRIVATE_IP_PATTERN, anonymized)):
            val = match.group(0)
            if val not in mapping.values():
                placeholder = f"[INTERNAL_IP_{ip_counter}]"
                mapping[placeholder] = val
                anonymized = anonymized.replace(val, placeholder)
                ip_counter += 1

        # 3. Tokenize Absolute System Paths
        for match in list(re.finditer(self.PATH_PATTERN, anonymized)):
            val = match.group(0)
            if val not in mapping.values():
                placeholder = f"[LOCAL_PATH_{path_counter}]"
                mapping[placeholder] = val
                anonymized = anonymized.replace(val, placeholder)
                path_counter += 1

        return anonymized, mapping

    def de_anonymize(self, response_text: str, mapping: Dict[str, str]) -> str:
        """
        Restores tokenized placeholders back to their original local values.
        Executed entirely in client-side memory before rendering to the user or IDE.
        """
        restored = response_text
        for placeholder, original in mapping.items():
            restored = restored.replace(placeholder, original)
        return restored

    @classmethod
    def mask_ip_for_logs(cls, text: str) -> str:
        """
        Masks any IPv4 address in console logs or diagnostics to enforce Zero-IP exposure.
        Example: 'Failing over to http://192.168.0.188:8090' -> 'Failing over to http://[SECURE_NODE]:8090'
        """
        if not text:
            return ""
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.sub(ipv4_pattern, "[SECURE_NODE]", text)

