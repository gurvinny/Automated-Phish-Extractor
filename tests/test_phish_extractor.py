import os
import sys
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock

# Add deps and root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "deps")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import phish_extractor


class TestPhishExtractor(unittest.TestCase):

    def test_defang_url(self):
        url = "http://example-phish.com/login?id=123"
        defanged = phish_extractor.defang_url(url)
        self.assertIn("hxxp://", defanged)
        self.assertIn("[.]", defanged)

    def test_defang_ip(self):
        ip = "192.168.1.1"
        defanged = phish_extractor.defang_ip(ip)
        self.assertIn("[.]", defanged)

    def test_defang_domain(self):
        domain = "malicious-site.com"
        defanged = phish_extractor.defang_domain(domain)
        self.assertEqual(defanged, "malicious-site[.]com")

    def test_parse_eml_headers(self):
        sample_eml = Path(__file__).parent.parent / "samples" / "mock_phish.eml"
        msg = phish_extractor.parse_eml(sample_eml)
        headers = phish_extractor.extract_headers(msg)
        attach = phish_extractor.extract_attachments(msg)

        self.assertIn("URGENT", headers.subject)
        self.assertEqual(headers.spf_result, "fail")
        self.assertEqual(headers.dmarc_result, "fail")
        self.assertTrue(len(attach) > 0)
        self.assertEqual(attach[0].filename, "Invoice_78291.pdf")

    def test_attachment_filename_is_sanitized(self):
        self.assertEqual(
            phish_extractor.sanitize_attachment_filename("../../dropper.exe"),
            "dropper.exe",
        )
        self.assertEqual(
            phish_extractor.sanitize_attachment_filename(r"C:\Users\Public\dropper.exe"),
            "dropper.exe",
        )
        self.assertEqual(
            phish_extractor.sanitize_attachment_filename(r"..\payload.exe"),
            "payload.exe",
        )

    @patch("phish_extractor.query_virustotal_url")
    @patch("phish_extractor.query_abuseipdb")
    def test_threat_intel_mock(self, mock_abuse, mock_vt):
        mock_vt.return_value = {
            "source": "VirusTotal",
            "ioc": "hxxp://secure-update[.]com",
            "malicious": True,
            "details": "12/90 engine detections",
            "error": None,
        }
        mock_abuse.return_value = {
            "source": "AbuseIPDB",
            "ioc": "198.51.100.42",
            "malicious": True,
            "details": "Abuse confidence score: 85%",
            "error": None,
        }
        res_vt = phish_extractor.query_virustotal_url("http://secure-update.com")
        res_ip = phish_extractor.query_abuseipdb("198.51.100.42")
        self.assertTrue(res_vt["malicious"])
        self.assertTrue(res_ip["malicious"])


if __name__ == "__main__":
    unittest.main()
