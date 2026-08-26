import email
import email.policy
import logging
import os
import sys
import tempfile
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

    def test_header_blob_iocs_are_scanned(self):
        raw_eml = """From: "Alert Team" <alerts@evil-phish.example>
Return-Path: <bounce@evil-phish.example>
Reply-To: "Support" <support@reply-evil.example>
X-Originating-IP: [8.8.8.8]
X-Mailer: Mailer from mail.evil-phish.example
Received: from mail.evil-phish.example (mail.evil-phish.example [1.1.1.1])
Subject: Test
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello
"""
        msg = email.message_from_string(raw_eml, policy=email.policy.default)
        headers = phish_extractor.extract_headers(msg)
        blob = phish_extractor.build_header_ioc_blob(msg, headers)
        iocs = phish_extractor.extract_iocs(blob)

        self.assertIn("evil-phish.example", iocs.domains)
        self.assertIn("reply-evil.example", iocs.domains)
        self.assertIn("8.8.8.8", iocs.ipv4_addresses)
        self.assertIn("1.1.1.1", iocs.ipv4_addresses)

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

    def test_parse_eml_rejects_oversized_input(self):
        with tempfile.NamedTemporaryFile(suffix=".eml") as eml_file:
            eml_file.write(b"A" * 11)
            eml_file.flush()
            with patch.object(phish_extractor, "MAX_EML_SIZE_BYTES", 10), patch.object(
                phish_extractor, "MAX_EML_SIZE_MB", 1
            ):
                with self.assertRaisesRegex(ValueError, "size limit"):
                    phish_extractor.parse_eml(Path(eml_file.name))

    def test_secret_redaction_filter(self):
        redactor = phish_extractor.SecretRedactionFilter(["vt-secret", "abuse-secret"])
        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname=__file__,
            lineno=1,
            msg="headers=%s key=%s",
            args=("vt-secret", "abuse-secret"),
            exc_info=None,
        )
        redactor.filter(record)
        self.assertNotIn("vt-secret", record.getMessage())
        self.assertNotIn("abuse-secret", record.getMessage())
        self.assertEqual(record.getMessage(), "headers=[REDACTED] key=[REDACTED]")

    @patch("phish_extractor.query_virustotal_url")
    def test_rate_limit_backoff_retries_lookup(self, mock_vt):
        # Use the injection points the function provides rather than patching
        # time.sleep globally, which would stall any concurrently running code.
        slept: list[float] = []
        first = phish_extractor.ThreatIntelResult(
            ioc="http://secure-update.com",
            source="VirusTotal",
            error="Rate-limited (HTTP 429) — retry later",
            rate_limited=True,
        )
        second = phish_extractor.ThreatIntelResult(
            ioc="http://secure-update.com",
            source="VirusTotal",
            malicious=True,
        )
        mock_vt.side_effect = [first, second]

        result = phish_extractor._with_rate_limit_backoff(
            phish_extractor.query_virustotal_url,
            "URL http://secure-update.com",
            "http://secure-update.com",
            base_delay_seconds=2.0,
            sleep_fn=slept.append,
            jitter_fn=lambda _lo, _hi: 0.0,
        )

        self.assertEqual(mock_vt.call_count, 2)
        self.assertEqual(slept, [2.0])
        self.assertTrue(result.malicious)

    @patch("phish_extractor.query_virustotal_url")
    def test_rate_limit_budget_stops_retrying_once_quota_is_spent(self, mock_vt):
        """After MAX_CONSECUTIVE_RATE_LIMITS, later IOCs must not sleep."""
        slept: list[float] = []
        mock_vt.side_effect = lambda *_a: phish_extractor.ThreatIntelResult(
            ioc="http://x.test",
            source="VirusTotal",
            error="Rate-limited (HTTP 429) — retry later",
            rate_limited=True,
        )
        budget = phish_extractor.RateLimitBudget(max_consecutive=1)

        for _ in range(3):
            phish_extractor._with_rate_limit_backoff(
                phish_extractor.query_virustotal_url,
                "URL http://x.test",
                "http://x.test",
                base_delay_seconds=2.0,
                sleep_fn=slept.append,
                jitter_fn=lambda _lo, _hi: 0.0,
                budget=budget,
            )

        # Only the first IOC pays the retry ladder; the rest return at once.
        self.assertEqual(len(slept), 3)
        self.assertTrue(budget.exhausted)

    def test_error_penalty_cannot_force_critical(self):
        """A total provider outage must not drive a benign message to CRITICAL."""
        headers = phish_extractor.EmailHeaders(
            spf_result="pass", dkim_result="pass", dmarc_result="pass"
        )
        intel = [
            phish_extractor.ThreatIntelResult(
                ioc=f"host{i}.test", source="VirusTotal", error="VT_API_KEY not set"
            )
            for i in range(10)
        ]
        verdict = phish_extractor.calculate_risk(headers, intel)
        self.assertNotEqual(verdict, "CRITICAL")

    def test_ipv6_extraction_preserves_compressed_addresses(self):
        text = "hop via 2001:4860:4864:20::34 and fe80::1ff:fe23:4567:890a here"
        found = set(phish_extractor.IPV6_PATTERN.findall(text))
        self.assertIn("2001:4860:4864:20::34", found)
        self.assertNotIn("2001:4860:4864:20::", found)

    def test_non_global_ipv6_is_filtered(self):
        self.assertFalse(phish_extractor._is_routable_ipv6("fe80::1"))
        self.assertFalse(phish_extractor._is_routable_ipv6("fd00::1"))
        self.assertTrue(phish_extractor._is_routable_ipv6("2001:4860:4864:20::34"))

    def test_received_header_does_not_leak_recipient_infrastructure(self):
        """Only the sending half of a Received hop may become an IOC."""
        received = (
            "from mail.evil.example (mail.evil.example [203.0.113.9])\n"
            "    by mx.ourcompany.example with ESMTP id 12345abcd\n"
            "    for <victim@ourcompany.example>; Wed, 11 Mar 2026 10:00:00 -0400"
        )
        clause = phish_extractor._sender_clause(received)
        self.assertIn("mail.evil.example", clause)
        self.assertNotIn("ourcompany.example", clause)
        self.assertNotIn("victim@", clause)

    def test_sender_clause_ignores_hop_without_from(self):
        self.assertEqual(
            phish_extractor._sender_clause("by mx.ourcompany.example with ESMTP"), ""
        )

    def test_rate_limit_detection_ignores_429_inside_urls(self):
        """A 503 on a host containing '429' must not be treated as a quota error."""
        result = phish_extractor.ThreatIntelResult(
            ioc="shop429.com",
            source="VirusTotal",
            error=(
                "Request failed: 503 Server Error: Service Unavailable "
                "for url: https://www.virustotal.com/api/v3/domains/shop429.com"
            ),
        )
        self.assertFalse(phish_extractor._is_rate_limited_result(result))

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
            "ioc": "1.1.1.1",
            "malicious": True,
            "details": "Abuse confidence score: 85%",
            "error": None,
        }
        res_vt = phish_extractor.query_virustotal_url("http://secure-update.com")
        res_ip = phish_extractor.query_abuseipdb("1.1.1.1")
        self.assertTrue(res_vt["malicious"])
        self.assertTrue(res_ip["malicious"])


if __name__ == "__main__":
    unittest.main()
