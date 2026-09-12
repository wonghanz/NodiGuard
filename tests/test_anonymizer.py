import unittest
from nodiguard.anonymizer import TokenAnonymizer

class TestTokenAnonymizer(unittest.TestCase):
    def setUp(self):
        self.anonymizer = TokenAnonymizer()

    def test_email_and_ip_tokenization(self):
        raw = "Deploy proxy to 192.168.1.105 and notify admin@mycompany.org immediately."
        anonymized, mapping = self.anonymizer.anonymize(raw)

        # Confirm sensitive strings are replaced
        self.assertNotIn("192.168.1.105", anonymized)
        self.assertNotIn("admin@mycompany.org", anonymized)
        self.assertIn("[INTERNAL_IP_1]", anonymized)
        self.assertIn("[MASKED_EMAIL_1]", anonymized)

        # Confirm mapping table contains correct values
        self.assertEqual(mapping["[INTERNAL_IP_1]"], "192.168.1.105")
        self.assertEqual(mapping["[MASKED_EMAIL_1]"], "admin@mycompany.org")

        # Test local client-side de-anonymization
        cloud_mock_response = "Successfully deployed to [INTERNAL_IP_1] and emailed [MASKED_EMAIL_1]."
        restored = self.anonymizer.de_anonymize(cloud_mock_response, mapping)
        self.assertEqual(restored, "Successfully deployed to 192.168.1.105 and emailed admin@mycompany.org.")

    def test_file_path_tokenization(self):
        raw = r"Error log stored at C:\Users\developer\projects\secret\log.txt"
        anonymized, mapping = self.anonymizer.anonymize(raw)

        self.assertNotIn(r"C:\Users\developer", anonymized)
        self.assertIn("[LOCAL_PATH_1]", anonymized)

        restored = self.anonymizer.de_anonymize(anonymized, mapping)
        self.assertEqual(restored, raw)

if __name__ == "__main__":
    unittest.main()
