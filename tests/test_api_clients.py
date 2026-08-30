import pytest
import responses
import base64
from phish_extractor import query_virustotal_url, query_abuseipdb, ThreatIntelResult

@responses.activate
def test_virustotal_get_mocked_200(monkeypatch):
    monkeypatch.setattr('phish_extractor.VT_API_KEY', 'dummy_key')
    
    url = "http://evil.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    responses.add(
        responses.GET,
        endpoint,
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 8, "undetected": 10}}}},
        status=200
    )
    
    result = query_virustotal_url(url)
    assert result.malicious is True
    assert result.detection_ratio == "8/18"

@responses.activate
def test_virustotal_get_mocked_401(monkeypatch):
    monkeypatch.setattr('phish_extractor.VT_API_KEY', 'dummy_key')
    
    url = "http://evil.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    responses.add(responses.GET, endpoint, status=401)
    
    result = query_virustotal_url(url)
    assert result.error == "Invalid API key (HTTP 401)"

@responses.activate
def test_virustotal_get_mocked_429(monkeypatch):
    monkeypatch.setattr('phish_extractor.VT_API_KEY', 'dummy_key')
    
    url = "http://evil.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    responses.add(responses.GET, endpoint, status=429)
    
    result = query_virustotal_url(url)
    assert result.error == "Rate-limited (HTTP 429) — retry later"

@responses.activate
def test_virustotal_get_mocked_404(monkeypatch):
    monkeypatch.setattr('phish_extractor.VT_API_KEY', 'dummy_key')
    
    url = "http://evil.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    responses.add(responses.GET, endpoint, status=404)
    
    result = query_virustotal_url(url)
    assert result.error == "Not found in VirusTotal database"

@responses.activate
def test_query_abuseipdb_malicious(monkeypatch):
    monkeypatch.setattr('phish_extractor.ABUSEIPDB_API_KEY', 'dummy_key')
    
    ip = "1.2.3.4"
    endpoint = f"https://api.abuseipdb.com/api/v2/check"
    
    responses.add(
        responses.GET,
        endpoint,
        json={"data": {"abuseConfidenceScore": 75}},
        status=200
    )
    
    result = query_abuseipdb(ip)
    assert result.malicious is True
    assert result.abuse_confidence == 75

@responses.activate
def test_query_abuseipdb_benign(monkeypatch):
    monkeypatch.setattr('phish_extractor.ABUSEIPDB_API_KEY', 'dummy_key')
    
    ip = "5.6.7.8"
    endpoint = f"https://api.abuseipdb.com/api/v2/check"
    
    responses.add(
        responses.GET,
        endpoint,
        json={"data": {"abuseConfidenceScore": 74}},
        status=200
    )
    
    result = query_abuseipdb(ip)
    assert result.malicious is False
    assert result.abuse_confidence == 74
