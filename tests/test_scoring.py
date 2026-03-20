import pytest
from phish_extractor import calculate_risk, EmailHeaders, ThreatIntelResult

def test_calculate_risk_low():
    headers = EmailHeaders(spf_result="pass", dkim_result="pass", dmarc_result="pass")
    intel = []
    assert calculate_risk(headers, intel) == "LOW"

def test_calculate_risk_medium():
    headers = EmailHeaders(spf_result="fail", dkim_result="pass", dmarc_result="pass")
    intel = [ThreatIntelResult(ioc="x", source="x", error="timeout")]
    # score = 2 (spf fail) + 1 (error) = 3 -> MEDIUM
    assert calculate_risk(headers, intel) == "MEDIUM"

def test_calculate_risk_high():
    headers = EmailHeaders(spf_result="fail", dkim_result="fail", dmarc_result="fail")
    intel = []
    # score = 6 -> HIGH
    assert calculate_risk(headers, intel) == "HIGH"

def test_calculate_risk_critical():
    headers = EmailHeaders(spf_result="fail", dkim_result="fail", dmarc_result="fail")
    intel = [
        ThreatIntelResult(ioc="1.1.1.1", source="AbuseIPDB", malicious=True),
        ThreatIntelResult(ioc="evil.com", source="VirusTotal", malicious=True)
    ]
    # score = 6 + 3 + 3 = 12 -> CRITICAL
    assert calculate_risk(headers, intel) == "CRITICAL"
