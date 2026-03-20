import pytest
from phish_extractor import extract_iocs

def test_extract_iocs():
    text = """
    Check out this link: https://evil.com/login?id=123
    Another one: http://phish.net/x
    Here is a domain: malicious-domain.co.uk
    Internal IP: http://10.0.0.1/ and 192.168.1.1
    Public IP: 8.8.8.8
    And an IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    """
    
    iocs = extract_iocs(text)
    
    assert "https://evil.com/login?id=123" in iocs.urls
    assert "http://phish.net/x" in iocs.urls
    
    # URL domains should be excluded from `domains` list
    assert "evil.com" not in iocs.domains
    assert "phish.net" not in iocs.domains
    
    assert "malicious-domain.co.uk" in iocs.domains
    
    assert "8.8.8.8" in iocs.ipv4_addresses
    assert "10.0.0.1" not in iocs.ipv4_addresses
    assert "192.168.1.1" not in iocs.ipv4_addresses
    
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in iocs.ipv6_addresses
