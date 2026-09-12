import unittest
from unittest.mock import patch, MagicMock
from nodiguard.waf_enforcer import CloudflareWAFEnforcer

class TestCloudflareWAFEnforcer(unittest.TestCase):
    def setUp(self):
        self.enforcer = CloudflareWAFEnforcer(zone_id="test_zone_123", api_token="test_token_456")

    @patch("nodiguard.waf_enforcer.requests.post")
    def test_ban_ip_with_cloudflare_sync(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"result": {"id": "cf_rule_abc123"}}
        mock_post.return_value = mock_resp

        attacker_ip = "198.51.100.77"
        res = self.enforcer.ban_ip(attacker_ip, reason="Frida hook detected")
        self.assertTrue(res["success"])
        self.assertTrue(res["cf_synced"])
        self.assertEqual(res["cf_rule_id"], "cf_rule_abc123")

        # Verify is_banned
        self.assertTrue(self.enforcer.is_banned(attacker_ip))

        # Cleanup
        self.enforcer.unban_ip(attacker_ip)
        self.assertFalse(self.enforcer.is_banned(attacker_ip))

    def test_reject_localhost_banning(self):
        res = self.enforcer.ban_ip("127.0.0.1")
        self.assertFalse(res["success"])
        self.assertIn("localhost", res["error"])

if __name__ == "__main__":
    unittest.main()
