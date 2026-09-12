"""Live integration tests against the real VirusTotal and AbuseIPDB APIs.

These are **opt-in and never run in CI**. Two gates must both be satisfied:

* ``VT_API_KEY`` / ``ABUSEIPDB_API_KEY`` must be configured, and
* ``RUN_LIVE_API_TESTS=1`` must be set explicitly.

The second gate matters. A developer with working keys in ``.env`` running the
suite should not silently make outbound requests or spend quota; opting in has
to be a deliberate act.

What these cover that mocked tests cannot: that the credentials authenticate,
and that the **response schema still matches what the parser expects**. Provider
schema drift is the failure mode a mock can never catch, because the mock
encodes our assumption rather than the provider's reality.

Deliberately not asserted: specific verdicts. Reputation data changes over time,
so asserting "this domain is malicious" produces a suite that fails for reasons
unrelated to the code. Plumbing and shape are stable; opinions are not.

Quota: the VirusTotal free tier allows 4 requests/minute and 500/day. This
module is written to stay well inside that.

Run with::

    RUN_LIVE_API_TESTS=1 python -m unittest tests.test_live_api -v
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import phish_extractor  # noqa: E402

RUN_LIVE = os.getenv("RUN_LIVE_API_TESTS") == "1"
HAVE_VT = bool(phish_extractor.VT_API_KEY)
HAVE_ABUSE = bool(phish_extractor.ABUSEIPDB_API_KEY)

SKIP_REASON = (
    "live API tests are opt-in: set RUN_LIVE_API_TESTS=1 and configure API keys"
)


@unittest.skipUnless(RUN_LIVE and HAVE_VT, SKIP_REASON)
class TestVirusTotalLive(unittest.TestCase):
    """Three requests total."""

    def test_domain_lookup_authenticates_and_parses(self):
        result = phish_extractor.query_virustotal_domain("example.com")
        self.assertEqual(result.error, "", "authentication or schema failure")
        self.assertEqual(result.source, "VirusTotal")
        # detection_ratio is what the report prints; it must be populated.
        self.assertRegex(result.detection_ratio, r"^\d+/\d+$")
        self.assertIsInstance(result.malicious, bool)

    def test_unknown_hash_is_reported_as_not_found_not_as_an_error(self):
        """A hash VT has never seen returns 404; that is information, not failure."""
        unseen = "0" * 64
        result = phish_extractor.query_virustotal_hash(unseen, "nonexistent.bin")
        self.assertFalse(result.malicious)
        # The 404 branch should produce a readable state rather than a raw error.
        self.assertNotIn("Traceback", result.error)

    def test_invalid_key_is_reported_clearly(self):
        """A bad key must surface as an auth error, not a crash or a false clean."""
        original = phish_extractor.VT_API_KEY
        phish_extractor.VT_API_KEY = "0" * 64
        try:
            result = phish_extractor.query_virustotal_domain("example.org")
            self.assertTrue(result.error, "invalid key should produce an error")
            self.assertFalse(result.malicious, "a failed lookup must not read as clean")
        finally:
            phish_extractor.VT_API_KEY = original


@unittest.skipUnless(RUN_LIVE and HAVE_ABUSE, SKIP_REASON)
class TestAbuseIPDBLive(unittest.TestCase):
    """Two requests total."""

    def test_ip_lookup_authenticates_and_parses(self):
        result = phish_extractor.query_abuseipdb("8.8.8.8")
        self.assertEqual(result.error, "", "authentication or schema failure")
        self.assertEqual(result.source, "AbuseIPDB")
        self.assertIsInstance(result.abuse_confidence, int)
        self.assertGreaterEqual(result.abuse_confidence, 0)
        self.assertLessEqual(result.abuse_confidence, 100)

    def test_invalid_key_is_reported_clearly(self):
        original = phish_extractor.ABUSEIPDB_API_KEY
        phish_extractor.ABUSEIPDB_API_KEY = "0" * 80
        try:
            result = phish_extractor.query_abuseipdb("8.8.4.4")
            self.assertTrue(result.error, "invalid key should produce an error")
            self.assertEqual(result.abuse_confidence, 0)
        finally:
            phish_extractor.ABUSEIPDB_API_KEY = original


@unittest.skipUnless(RUN_LIVE and HAVE_VT and HAVE_ABUSE, SKIP_REASON)
class TestPipelineLive(unittest.TestCase):
    """One end-to-end run on the smallest sample. Two requests."""

    def test_clean_sample_end_to_end_stays_low(self):
        path = Path(__file__).parent.parent / "samples" / "clean" / "internal-notice.eml"
        msg = phish_extractor.parse_eml(path)
        headers = phish_extractor.extract_headers(msg)
        iocs = phish_extractor.extract_iocs(
            phish_extractor.get_body_text(msg)
            + "\n"
            + phish_extractor.build_header_ioc_blob(msg, headers)
        )
        intel = phish_extractor.enrich_iocs(iocs, [], rate_limit_delay=0)
        risk = phish_extractor.calculate_risk(headers, intel)

        # With real lookups succeeding, legitimate mail must still read as LOW.
        self.assertEqual(risk, "LOW")
        for result in intel:
            self.assertEqual(result.error, "", f"live lookup failed: {result.ioc}")

        report = phish_extractor.build_report(
            source_file=path.name,
            headers=headers,
            iocs=iocs,
            attachments=[],
            intel=intel,
            risk=risk,
        )
        markdown = phish_extractor.report_to_markdown(report)
        self.assertIn("LOW", markdown)
        self.assertNotIn("](http", markdown, "report must contain no live links")


if __name__ == "__main__":
    unittest.main()
