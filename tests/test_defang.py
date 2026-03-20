import pytest
from phish_extractor import defang_url, defang_domain, defang_ip

def test_defang_url():
    assert defang_url("http://evil.com/path.html") == "hxxp://evil[.]com/path.html"
    assert defang_url("https://malicious.co.uk/x.php") == "hxxps://malicious[.]co[.]uk/x.php"
    assert defang_url("https://1.2.3.4/abc") == "hxxps://1[.]2[.]3[.]4/abc"

def test_defang_domain():
    assert defang_domain("evil.com") == "evil[.]com"
    assert defang_domain("malicious.co.uk") == "malicious[.]co[.]uk"

def test_defang_ip():
    assert defang_ip("8.8.8.8") == "8[.]8[.]8[.]8"
    assert defang_ip("2001:db8::1") == "2001:db8::1" # IPv6 has no dots, should remain unchanged if no dots
    
    # But if mapped ipv4
    assert defang_ip("::ffff:192.168.1.1") == "::ffff:192[.]168[.]1[.]1"
