"""
NodiGuard Cloudflare WAF Automated Enforcement Engine.
Detects mobile app decompilation, dynamic hooks (Frida), and honeypot traps.
Immediately dispatches automated IP ban rules to Cloudflare Global Edge WAF.
"""

import os
import sys
import json
import time
import requests
from pathlib import Path
from typing import Dict, Any, List, Optional

class CloudflareWAFEnforcer:
    def __init__(self, zone_id: Optional[str] = None, api_token: Optional[str] = None):
        self.zone_id = zone_id or os.environ.get("CLOUDFLARE_ZONE_ID", "")
        self.api_token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN", "")
        
        # Local quarantine storage
        home_dir = Path.home() / ".nodiguard"
        home_dir.mkdir(parents=True, exist_ok=True)
        self.blacklist_file = home_dir / "banned_ips.json"
        self._ensure_storage()

    def _ensure_storage(self):
        if not self.blacklist_file.exists():
            with open(self.blacklist_file, "w", encoding="utf-8") as f:
                json.dump([], f)

    def _load_blacklist(self) -> List[Dict[str, Any]]:
        try:
            with open(self.blacklist_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_blacklist(self, records: List[Dict[str, Any]]):
        try:
            with open(self.blacklist_file, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
        except Exception as e:
            print(f"[!] Failed to save local blacklist: {e}")

    def is_banned(self, ip_address: str) -> bool:
        """Checks if an IP address is currently quarantined locally."""
        records = self._load_blacklist()
        return any(r.get("ip") == ip_address for r in records)

    def ban_ip(self, ip_address: str, reason: str = "Reverse Engineering / Honeytoken triggered") -> Dict[str, Any]:
        """
        Bans an attacker's IP address both locally and across Cloudflare Global Edge WAF.
        """
        clean_ip = ip_address.strip()
        if not clean_ip or clean_ip in ("127.0.0.1", "::1", "localhost"):
            return {"success": False, "error": "Cannot ban localhost loopback address"}

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        record = {
            "ip": clean_ip,
            "reason": reason,
            "timestamp": timestamp,
            "cf_rule_id": None,
            "cf_synced": False
        }

        # 1. Update Local Quarantine Table
        records = self._load_blacklist()
        if not any(r.get("ip") == clean_ip for r in records):
            records.append(record)
            self._save_blacklist(records)

        # 2. Dispatch IP Access Block Rule to Cloudflare WAF (if API credentials available)
        if self.zone_id and self.api_token:
            url = f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/firewall/access_rules/rules"
            headers = {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json"
            }
            payload = {
                "mode": "block",
                "configuration": {
                    "target": "ip",
                    "value": clean_ip
                },
                "notes": f"[NODIGUARD AUTO-BAN]: {reason}"
            }
            try:
                resp = requests.post(url, json=payload, headers=headers, timeout=10)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    cf_rule_id = data.get("result", {}).get("id")
                    record["cf_rule_id"] = cf_rule_id
                    record["cf_synced"] = True
                    # Update local record with cf_rule_id
                    for r in records:
                        if r.get("ip") == clean_ip:
                            r["cf_rule_id"] = cf_rule_id
                            r["cf_synced"] = True
                    self._save_blacklist(records)
                else:
                    record["error"] = f"Cloudflare API returned {resp.status_code}: {resp.text}"
            except Exception as e:
                record["error"] = f"Cloudflare dispatch failed: {str(e)}"

        return {
            "success": True,
            "ip": clean_ip,
            "cf_synced": record.get("cf_synced", False),
            "cf_rule_id": record.get("cf_rule_id"),
            "timestamp": timestamp
        }

    def list_banned_ips(self) -> List[Dict[str, Any]]:
        """Returns all quarantined attacker IPs."""
        return self._load_blacklist()

    def unban_ip(self, ip_address: str) -> bool:
        """Removes an IP address from local quarantine and Cloudflare WAF."""
        records = self._load_blacklist()
        matched = [r for r in records if r.get("ip") == ip_address]
        if not matched:
            return False

        cf_rule_id = matched[0].get("cf_rule_id")
        if cf_rule_id and self.zone_id and self.api_token:
            url = f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}/firewall/access_rules/rules/{cf_rule_id}"
            headers = {"Authorization": f"Bearer {self.api_token}"}
            try:
                requests.delete(url, headers=headers, timeout=10)
            except Exception:
                pass

        new_records = [r for r in records if r.get("ip") != ip_address]
        self._save_blacklist(new_records)
        return True
